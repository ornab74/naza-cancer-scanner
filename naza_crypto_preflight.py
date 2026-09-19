"""Fail-closed runtime check for the pinned production cryptographic backend."""
import hmac
import os
from importlib.metadata import version as package_version

import oqs
from argon2.low_level import ARGON2_VERSION, Type as Argon2Type, hash_secret_raw
from cryptography import __version__ as cryptography_version
from cryptography.hazmat.backends.openssl.backend import backend as openssl_backend

import spooky_combiner as combiner
import spooky_trihybrid as tri


def main():
    expected = {
        "cryptography": "46.0.7",
        "argon2-cffi": "25.1.0",
        "argon2-cffi-bindings": "25.1.0",
    }
    installed = {
        "cryptography": cryptography_version,
        "argon2-cffi": package_version("argon2-cffi"),
        "argon2-cffi-bindings": package_version("argon2-cffi-bindings"),
    }
    if installed != expected:
        raise SystemExit("ERROR: cryptographic package identity mismatch: " + repr(installed))
    openssl_text = openssl_backend.openssl_version_text()
    if not openssl_text.startswith(("OpenSSL 3.", "OpenSSL 4.")):
        raise SystemExit("ERROR: unsupported cryptographic backend: " + openssl_text)
    probe = hash_secret_raw(b"naza-preflight", b"naza-argon2-salt", 1, 8192, 1, 32,
                            Argon2Type.ID, ARGON2_VERSION)
    if len(probe) != 32:
        raise SystemExit("ERROR: Argon2id backend self-test failed")
    version = oqs.oqs_version()
    if version != "0.14.0":
        raise SystemExit("ERROR: expected liboqs 0.14.0, found " + str(version))
    status = combiner.status(oqs)
    if not status.ready:
        raise SystemExit("ERROR: required liboqs KEMs unavailable: " + ", ".join(status.missing))

    payload = os.urandom(32)
    protector = os.urandom(32)
    context = b"naza/runtime-preflight/v1"
    envelope = tri.create_envelope(payload, protector, oqs, context)
    recovered = tri.open_envelope(envelope, protector, oqs, context)
    if not hmac.compare_digest(payload, recovered):
        raise SystemExit("ERROR: tri-hybrid runtime self-test failed")
    tampered = bytearray(envelope)
    tampered[-1] ^= 1
    try:
        tri.open_envelope(bytes(tampered), protector, oqs, context)
    except combiner.SpookyCombinerError:
        return
    raise SystemExit("ERROR: tri-hybrid runtime accepted a tampered envelope")


if __name__ == "__main__":
    main()
