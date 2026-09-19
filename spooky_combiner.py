"""SpookyCombiner-1 research KEM combiner for Naza.

EXPERIMENTAL RESEARCH CODE. NOT A NIST STANDARD. NOT FOR PRODUCTION SECURITY.

The construction combines ML-KEM-1024 and HQC-256 shared secrets with
transcript-bound HKDF-SHA512, separates wrapping and confirmation keys,
seals each exported KEM secret key under an external 256-bit protector,
and intentionally presents one generic authentication failure path.

The module does not import liboqs itself. Callers pass the imported ``oqs``
module so Naza can remain usable when liboqs is absent.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"SPK1\n"
VERSION = 1
SUITE = "SpookyCombiner-1/ML-KEM-1024+HQC-256/HKDF-SHA512/AES-256-GCM"
KEMS = ("ML-KEM-1024", "HQC-256")
CONTEXT = b"naza/spooky-combiner-1/research-key-envelope/v1"
MAX_ENVELOPE = 256 * 1024
MAX_BLOB = 96 * 1024
MAX_PAYLOAD = 4096
CONFIRM_LEN = 32


class SpookyCombinerError(RuntimeError):
    """Generic error. Deliberately does not identify the failed branch."""


@dataclass(frozen=True)
class Status:
    ready: bool
    enabled: Tuple[str, ...]
    missing: Tuple[str, ...]


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA512(), length=length, salt=salt, info=info).derive(ikm)


def _sha512(*chunks: bytes) -> bytes:
    h = hashlib.sha512()
    for chunk in chunks:
        h.update(chunk)
    return h.digest()


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _b64e(v: bytes) -> str:
    return base64.b64encode(v).decode("ascii")


def _b64d(v: Any, label: str, *, exact: int | None = None, maximum: int = MAX_BLOB) -> bytes:
    if not isinstance(v, str) or len(v) > (maximum * 2):
        raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed")
    try:
        raw = base64.b64decode(v.encode("ascii"), validate=True)
    except Exception as exc:
        raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed") from exc
    if exact is not None and len(raw) != exact:
        raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed")
    if len(raw) > maximum:
        raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed")
    return raw


def _zeroize(buf: Any) -> None:
    """Best effort only: Python runtimes may retain immutable/copy buffers."""
    try:
        if isinstance(buf, bytearray):
            for i in range(len(buf)):
                buf[i] = 0
        elif isinstance(buf, memoryview) and not buf.readonly:
            buf[:] = b"\x00" * len(buf)
    except Exception:
        pass


def status(oqs_module: Any) -> Status:
    if oqs_module is None:
        return Status(False, (), KEMS)
    try:
        enabled = tuple(str(x) for x in oqs_module.get_enabled_kem_mechanisms())
    except Exception:
        return Status(False, (), KEMS)
    missing = tuple(k for k in KEMS if k not in enabled)
    return Status(not missing, tuple(k for k in KEMS if k in enabled), missing)


def _strict_branch_public(branch: Dict[str, Any], expected_alg: str) -> Tuple[bytes, bytes]:
    if set(branch.keys()) != {"alg", "pk", "ct", "sk_nonce", "sk_ct"}:
        raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed")
    if branch.get("alg") != expected_alg:
        raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed")
    pk = _b64d(branch["pk"], "pk")
    ct = _b64d(branch["ct"], "ct")
    if not pk or not ct:
        raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed")
    return pk, ct


def _transcript(envelope_id: bytes, branches: List[Dict[str, Any]]) -> bytes:
    public_view = {
        "v": VERSION,
        "suite": SUITE,
        "context": CONTEXT.decode("ascii"),
        "id": _b64e(envelope_id),
        "branches": [
            {"alg": b["alg"], "pk": b["pk"], "ct": b["ct"]}
            for b in branches
        ],
    }
    return _sha512(b"SPK1/TRANSCRIPT\x00", _canon(public_view))


def _lane_extract(shared_secret: bytes, transcript: bytes, index: int, alg: str) -> bytes:
    salt = _sha512(b"SPK1/LANE-SALT\x00", transcript, index.to_bytes(1, "big"), alg.encode("ascii"))
    info = b"SPK1/LANE-EXTRACT\x00" + index.to_bytes(1, "big") + b"\x00" + alg.encode("ascii")
    return _hkdf(shared_secret, salt, info, 64)


def _combine(shared: List[bytes], transcript: bytes) -> Tuple[bytes, bytes]:
    if len(shared) != len(KEMS):
        raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed")
    lanes = [_lane_extract(shared[i], transcript, i, KEMS[i]) for i in range(len(KEMS))]
    root_salt = _sha512(b"SPK1/ROOT-SALT\x00", transcript)
    root = bytearray(_hkdf(b"".join(lanes), root_salt, b"SPK1/ROBUST-COMBINER-ROOT\x00", 64))
    try:
        wrap_key = _hkdf(bytes(root), transcript, b"SPK1/DATA-WRAP-KEY\x00", 32)
        confirm_key = _hkdf(bytes(root), transcript, b"SPK1/KEY-CONFIRMATION\x00", 32)
        return wrap_key, confirm_key
    finally:
        _zeroize(root)
        for lane in lanes:
            _zeroize(bytearray(lane))


def _branch_protector(protector_key: bytes, envelope_id: bytes, transcript: bytes, index: int, alg: str) -> bytes:
    salt = _sha512(b"SPK1/BRANCH-SEAL-SALT\x00", envelope_id, transcript)
    info = b"SPK1/BRANCH-SEAL\x00" + index.to_bytes(1, "big") + b"\x00" + alg.encode("ascii")
    return _hkdf(protector_key, salt, info, 32)


def _rejection_secret(protector_key: bytes, envelope_id: bytes, transcript: bytes, index: int, alg: str, ct: bytes) -> bytes:
    seed = _hkdf(
        protector_key,
        _sha512(b"SPK1/REJECT-SALT\x00", envelope_id),
        b"SPK1/REJECT-SEED\x00" + index.to_bytes(1, "big") + b"\x00" + alg.encode("ascii"),
        64,
    )
    try:
        return hmac.new(seed, b"SPK1/DECAP-REJECT\x00" + transcript + ct, hashlib.sha512).digest()
    finally:
        _zeroize(bytearray(seed))


def create_envelope(payload: bytes, protector_key: bytes, oqs_module: Any) -> bytes:
    """Create a two-KEM research envelope.

    ``protector_key`` is an external 32-byte local protection key. In Naza it is
    derived from the existing hardware/passphrase KEK; it protects exported KEM
    secret keys at rest. This construction does *not* turn a locally stored key
    file into a remotely-held PQ key system.
    """
    if not isinstance(payload, (bytes, bytearray)) or not (1 <= len(payload) <= MAX_PAYLOAD):
        raise ValueError("payload length out of range")
    if not isinstance(protector_key, (bytes, bytearray)) or len(protector_key) != 32:
        raise ValueError("protector_key must be 32 bytes")
    st = status(oqs_module)
    if not st.ready:
        raise SpookyCombinerError("SpookyCombiner-1 unavailable: missing " + ", ".join(st.missing))

    envelope_id = os.urandom(32)
    branches: List[Dict[str, Any]] = []
    secrets_: List[bytes] = []
    sks: List[bytearray] = []
    try:
        # First produce only transcript-visible branch material.
        for alg in KEMS:
            with oqs_module.KeyEncapsulation(alg) as recipient:
                pk = recipient.generate_keypair()
                sk = bytearray(recipient.export_secret_key())
            with oqs_module.KeyEncapsulation(alg) as sender:
                ct, ss = sender.encap_secret(pk)
            if not pk or not ct or not ss or len(pk) > MAX_BLOB or len(ct) > MAX_BLOB or len(sk) > MAX_BLOB:
                raise SpookyCombinerError("SpookyCombiner-1 envelope creation failed")
            sks.append(sk)
            secrets_.append(bytes(ss))
            branches.append({"alg": alg, "pk": _b64e(pk), "ct": _b64e(ct), "sk_nonce": "", "sk_ct": ""})

        transcript = _transcript(envelope_id, branches)

        # Seal each KEM secret key independently with a transcript-bound key/AAD.
        for i, alg in enumerate(KEMS):
            pk, ct = _strict_branch_public(branches[i], alg)
            seal_key = bytearray(_branch_protector(bytes(protector_key), envelope_id, transcript, i, alg))
            nonce = os.urandom(12)
            aad = b"SPK1/BRANCH-SK\x00" + transcript + i.to_bytes(1, "big") + alg.encode("ascii") + _sha512(pk, ct)
            try:
                sk_ct = AESGCM(bytes(seal_key)).encrypt(nonce, bytes(sks[i]), aad)
            finally:
                _zeroize(seal_key)
            branches[i]["sk_nonce"] = _b64e(nonce)
            branches[i]["sk_ct"] = _b64e(sk_ct)

        wrap_key, confirm_key = _combine(secrets_, transcript)
        data_nonce = os.urandom(12)
        data_aad = b"SPK1/DATA\x00" + transcript
        data_ct = AESGCM(wrap_key).encrypt(data_nonce, bytes(payload), data_aad)
        confirm = hmac.new(
            confirm_key,
            b"SPK1/CONFIRM\x00" + transcript + data_nonce + data_ct,
            hashlib.sha512,
        ).digest()[:CONFIRM_LEN]
        obj = {
            "v": VERSION,
            "suite": SUITE,
            "context": CONTEXT.decode("ascii"),
            "id": _b64e(envelope_id),
            "branches": branches,
            "data_nonce": _b64e(data_nonce),
            "data_ct": _b64e(data_ct),
            "confirm": _b64e(confirm),
        }
        out = MAGIC + _canon(obj)
        if len(out) > MAX_ENVELOPE:
            raise SpookyCombinerError("SpookyCombiner-1 envelope too large")
        return out
    except SpookyCombinerError:
        raise
    except Exception as exc:
        raise SpookyCombinerError("SpookyCombiner-1 envelope creation failed") from exc
    finally:
        for sk in sks:
            _zeroize(sk)
        for ss in secrets_:
            _zeroize(bytearray(ss))


def _parse(blob: bytes) -> Dict[str, Any]:
    if not isinstance(blob, (bytes, bytearray)) or len(blob) > MAX_ENVELOPE or not bytes(blob).startswith(MAGIC):
        raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed")
    def no_duplicates(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ValueError("duplicate JSON key")
            out[k] = v
        return out
    try:
        obj = json.loads(
            bytes(blob)[len(MAGIC):].decode("ascii"),
            object_pairs_hook=no_duplicates,
            parse_constant=lambda _x: (_ for _ in ()).throw(ValueError("non-finite JSON value")),
        )
    except Exception as exc:
        raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed") from exc
    required = {"v", "suite", "context", "id", "branches", "data_nonce", "data_ct", "confirm"}
    if not isinstance(obj, dict) or set(obj.keys()) != required:
        raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed")
    if type(obj["v"]) is not int or obj["v"] != VERSION:
        raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed")
    if type(obj["suite"]) is not str or obj["suite"] != SUITE:
        raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed")
    if type(obj["context"]) is not str or obj["context"] != CONTEXT.decode("ascii"):
        raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed")
    if not isinstance(obj["branches"], list) or len(obj["branches"]) != len(KEMS):
        raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed")
    return obj


def open_envelope(blob: bytes, protector_key: bytes, oqs_module: Any) -> bytes:
    """Authenticate, decapsulate both KEM branches, and decrypt the payload.

    Branch-specific errors are converted into deterministic pseudorandom fallback
    secrets and verification continues. The caller receives one generic failure.
    This reduces easy error-oracle leakage; Python cannot guarantee constant-time
    execution or memory erasure.
    """
    if not isinstance(protector_key, (bytes, bytearray)) or len(protector_key) != 32:
        raise ValueError("protector_key must be 32 bytes")
    st = status(oqs_module)
    if not st.ready:
        raise SpookyCombinerError("SpookyCombiner-1 unavailable: missing " + ", ".join(st.missing))

    obj = _parse(blob)
    envelope_id = _b64d(obj["id"], "id", exact=32, maximum=64)
    branches: List[Dict[str, Any]] = obj["branches"]
    public_parts: List[Tuple[bytes, bytes]] = []
    for i, alg in enumerate(KEMS):
        public_parts.append(_strict_branch_public(branches[i], alg))
    transcript = _transcript(envelope_id, branches)
    shared: List[bytes] = []
    hot: List[bytearray] = []

    try:
        for i, alg in enumerate(KEMS):
            pk, ct = public_parts[i]
            ss: bytes | None = None
            seal_key = bytearray(_branch_protector(bytes(protector_key), envelope_id, transcript, i, alg))
            try:
                nonce = _b64d(branches[i]["sk_nonce"], "sk_nonce", exact=12, maximum=32)
                sk_ct = _b64d(branches[i]["sk_ct"], "sk_ct")
                aad = b"SPK1/BRANCH-SK\x00" + transcript + i.to_bytes(1, "big") + alg.encode("ascii") + _sha512(pk, ct)
                sk = bytearray(AESGCM(bytes(seal_key)).decrypt(nonce, sk_ct, aad))
                hot.append(sk)
                with oqs_module.KeyEncapsulation(alg, bytes(sk)) as recipient:
                    ss = recipient.decap_secret(ct)
                if not ss:
                    raise ValueError("empty shared secret")
            except Exception:
                # Continue with a transcript-bound secret so all branch failures
                # converge on the same final authentication decision.
                ss = _rejection_secret(bytes(protector_key), envelope_id, transcript, i, alg, ct)
            finally:
                _zeroize(seal_key)
            shared.append(bytes(ss))

        wrap_key, confirm_key = _combine(shared, transcript)
        data_nonce = _b64d(obj["data_nonce"], "data_nonce", exact=12, maximum=32)
        data_ct = _b64d(obj["data_ct"], "data_ct", maximum=MAX_PAYLOAD + 64)
        supplied = _b64d(obj["confirm"], "confirm", exact=CONFIRM_LEN, maximum=64)
        expected = hmac.new(
            confirm_key,
            b"SPK1/CONFIRM\x00" + transcript + data_nonce + data_ct,
            hashlib.sha512,
        ).digest()[:CONFIRM_LEN]
        confirm_ok = hmac.compare_digest(expected, supplied)
        plaintext: bytes | None = None
        try:
            plaintext = AESGCM(wrap_key).decrypt(data_nonce, data_ct, b"SPK1/DATA\x00" + transcript)
        except Exception:
            plaintext = None
        if not confirm_ok or plaintext is None or not (1 <= len(plaintext) <= MAX_PAYLOAD):
            raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed")
        return plaintext
    except SpookyCombinerError:
        raise
    except Exception as exc:
        raise SpookyCombinerError("SpookyCombiner-1 envelope authentication failed") from exc
    finally:
        for ss in shared:
            _zeroize(bytearray(ss))
        for buf in hot:
            _zeroize(buf)


def self_test(oqs_module: Any) -> Dict[str, Any]:
    """Round-trip plus tamper-detection self-test. Generates fresh KEM keys."""
    protector = os.urandom(32)
    payload = os.urandom(32)
    blob = create_envelope(payload, protector, oqs_module)
    recovered = open_envelope(blob, protector, oqs_module)
    if not hmac.compare_digest(payload, recovered):
        raise SpookyCombinerError("SpookyCombiner-1 self-test round-trip failed")

    # Tamper with authenticated data while preserving syntactic validity.
    obj = _parse(blob)
    tampered_ct = bytearray(_b64d(obj["data_ct"], "data_ct"))
    tampered_ct[len(tampered_ct) // 2] ^= 0x01
    obj["data_ct"] = _b64e(bytes(tampered_ct))
    tampered = MAGIC + _canon(obj)
    tamper_rejected = False
    try:
        open_envelope(tampered, protector, oqs_module)
    except SpookyCombinerError:
        tamper_rejected = True
    if not tamper_rejected:
        raise SpookyCombinerError("SpookyCombiner-1 self-test accepted tampering")
    return {
        "suite": SUITE,
        "algorithms": list(KEMS),
        "round_trip": True,
        "tamper_rejected": True,
        "envelope_bytes": len(blob),
    }
