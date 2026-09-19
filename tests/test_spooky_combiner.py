import hashlib
import hmac
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import spooky_combiner as sc


class FakeKEM:
    """Structural test double only; NOT cryptography."""
    def __init__(self, alg, secret_key=None):
        if alg not in sc.KEMS:
            raise RuntimeError("disabled")
        self.alg = alg
        self.sk = bytes(secret_key) if secret_key is not None else None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def generate_keypair(self):
        self.sk = os.urandom(48)
        return hashlib.sha512(self.alg.encode() + self.sk).digest()

    def export_secret_key(self):
        return self.sk

    def encap_secret(self, pk):
        ct = os.urandom(64)
        ss = hmac.new(pk, self.alg.encode() + ct, hashlib.sha512).digest()
        return ct, ss

    def decap_secret(self, ct):
        pk = hashlib.sha512(self.alg.encode() + self.sk).digest()
        return hmac.new(pk, self.alg.encode() + ct, hashlib.sha512).digest()


class FakeOQS:
    KeyEncapsulation = FakeKEM

    @staticmethod
    def get_enabled_kem_mechanisms():
        return list(sc.KEMS)


def test_roundtrip_and_tamper():
    oqs = FakeOQS()
    protector = os.urandom(32)
    payload = os.urandom(64)
    blob = sc.create_envelope(payload, protector, oqs)
    assert sc.open_envelope(blob, protector, oqs) == payload

    tampered = bytearray(blob)
    tampered[-8] ^= 1
    try:
        sc.open_envelope(bytes(tampered), protector, oqs)
    except sc.SpookyCombinerError:
        pass
    else:
        raise AssertionError("tampered envelope accepted")


def test_wrong_protector_fails_generically():
    oqs = FakeOQS()
    blob = sc.create_envelope(os.urandom(32), os.urandom(32), oqs)
    try:
        sc.open_envelope(blob, os.urandom(32), oqs)
    except sc.SpookyCombinerError as e:
        assert "authentication failed" in str(e)
    else:
        raise AssertionError("wrong protector accepted")


def test_downgrade_rejected():
    oqs = FakeOQS()
    protector = os.urandom(32)
    blob = sc.create_envelope(os.urandom(32), protector, oqs)
    obj = sc._parse(blob)
    obj["branches"] = obj["branches"][:1]
    forged = sc.MAGIC + sc._canon(obj)
    try:
        sc.open_envelope(forged, protector, oqs)
    except sc.SpookyCombinerError:
        pass
    else:
        raise AssertionError("one-branch downgrade accepted")


if __name__ == "__main__":
    test_roundtrip_and_tamper()
    test_wrong_protector_fails_generically()
    test_downgrade_rejected()
    print("spooky_combiner structural tests: PASS")
