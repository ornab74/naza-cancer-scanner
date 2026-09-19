"""Experimental SpookyNaza: Spooky (ML-KEM-1024 + HQC-256), X25519, AES-GCM.

Local key envelope, not a network protocol or a validated cryptographic suite.
All private material remains protected by the caller's external protector.
"""
import hashlib
import os
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import spooky_combiner as sc

MAGIC = b"SPK3\n"
SUITE = b"SpookyNaza-1/ML-KEM-1024+HQC-256+X25519/HKDF-SHA512/AES-256-GCM"
MAX_ENVELOPE = sc.MAX_ENVELOPE + 8192
ERROR = "SpookyNaza tri-hybrid authentication failed"
MAX_CONTEXT = 1024


def _check_context(context):
    if not isinstance(context, bytes) or not 1 <= len(context) <= MAX_CONTEXT:
        raise ValueError("context must contain 1 to 1024 bytes")


def _public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _key(protector, transcript, label):
    return sc._hkdf(protector, transcript, SUITE + b"/" + label, 32)


def create_envelope(payload, protector, oqs_module, context=b""):
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= sc.MAX_PAYLOAD:
        raise ValueError("payload length out of range")
    if not isinstance(protector, bytes) or len(protector) != 32:
        raise ValueError("protector must be 32 bytes")
    _check_context(context)
    seed = os.urandom(32)
    spooky = sc.create_envelope(seed, protector, oqs_module)
    recipient, sender = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    header = MAGIC + struct.pack(">I", len(spooky)) + spooky + _public(recipient) + _public(sender)
    transcript = hashlib.sha512(SUITE + struct.pack(">I", len(context)) + context + header).digest()
    private = recipient.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    nonce = os.urandom(12)
    sealed = nonce + AESGCM(_key(protector, transcript, b"private")).encrypt(nonce, private, transcript)
    shared = sender.exchange(recipient.public_key())
    root = sc._hkdf(sc._hkdf(seed, transcript, SUITE + b"/spooky", 64) + sc._hkdf(shared, transcript, SUITE + b"/classical", 64), transcript, SUITE + b"/root", 32)
    nonce = os.urandom(12)
    return header + sealed + nonce + AESGCM(root).encrypt(nonce, payload, transcript + sealed)


def open_envelope(blob, protector, oqs_module, context=b""):
    try:
        if not isinstance(blob, bytes) or not 0 < len(blob) <= MAX_ENVELOPE or not blob.startswith(MAGIC):
            raise ValueError()
        if not isinstance(protector, bytes) or len(protector) != 32:
            raise ValueError()
        _check_context(context)
        size = struct.unpack(">I", blob[5:9])[0]
        end = 9 + size
        if not 0 < size <= sc.MAX_ENVELOPE or not end + 64 + 60 + 29 <= len(blob) <= end + 64 + 60 + 28 + sc.MAX_PAYLOAD:
            raise ValueError()
        header = blob[:end + 64]
        transcript = hashlib.sha512(SUITE + struct.pack(">I", len(context)) + context + header).digest()
        sealed = blob[end + 64:end + 124]
        private = AESGCM(_key(protector, transcript, b"private")).decrypt(sealed[:12], sealed[12:], transcript)
        recipient = X25519PrivateKey.from_private_bytes(private)
        if _public(recipient) != blob[end:end + 32]:
            raise ValueError()
        shared = recipient.exchange(X25519PublicKey.from_public_bytes(blob[end + 32:end + 64]))
        seed = sc.open_envelope(blob[9:end], protector, oqs_module)
        if len(seed) != 32:
            raise ValueError()
        root = sc._hkdf(sc._hkdf(seed, transcript, SUITE + b"/spooky", 64) + sc._hkdf(shared, transcript, SUITE + b"/classical", 64), transcript, SUITE + b"/root", 32)
        tail = blob[end + 124:]
        return AESGCM(root).decrypt(tail[:12], tail[12:], transcript + sealed)
    except Exception:
        raise sc.SpookyCombinerError(ERROR) from None
