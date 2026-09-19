import ast
import hashlib
import hmac
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import spooky_combiner as sc
import spooky_trihybrid as tri
import naza_storage as storage
from test_spooky_combiner import FakeOQS


class TriHybridTests(unittest.TestCase):
    def setUp(self):
        self.protector = os.urandom(32)
        self.context = b'NKEY4\x01\x00' + os.urandom(16)
        self.payload = os.urandom(32)
        self.blob = tri.create_envelope(self.payload, self.protector, FakeOQS(), self.context)

    def test_roundtrip(self):
        self.assertEqual(tri.open_envelope(self.blob, self.protector, FakeOQS(), self.context), self.payload)

    def test_tamper_each_component(self):
        end = 9 + int.from_bytes(self.blob[5:9], 'big')
        for offset in (0, 5, 9, end - 1, end, end + 32, end + 64, end + 76, end + 124, len(self.blob) - 1):
            with self.subTest(offset=offset):
                blob = bytearray(self.blob)
                blob[offset] ^= 1
                with self.assertRaisesRegex(sc.SpookyCombinerError, tri.ERROR):
                    tri.open_envelope(bytes(blob), self.protector, FakeOQS(), self.context)

    def test_wrong_gate_context_truncation_and_trailing_bytes(self):
        for blob, key, context in ((self.blob, os.urandom(32), self.context), (self.blob, self.protector, b'wrong'), (self.blob[:-1], self.protector, self.context), (self.blob + b'x', self.protector, self.context), (b'SPK3\n', self.protector, self.context)):
            with self.assertRaisesRegex(sc.SpookyCombinerError, tri.ERROR):
                tri.open_envelope(blob, key, FakeOQS(), context)

    def test_missing_pq_fails_closed(self):
        with self.assertRaises(sc.SpookyCombinerError):
            tri.create_envelope(self.payload, self.protector, None, self.context)
        with self.assertRaisesRegex(sc.SpookyCombinerError, tri.ERROR):
            tri.open_envelope(self.blob, self.protector, None, self.context)

    def test_context_is_required_and_bounded(self):
        with self.assertRaises(ValueError):
            tri.create_envelope(self.payload, self.protector, FakeOQS(), b"")
        with self.assertRaises(ValueError):
            tri.create_envelope(self.payload, self.protector, FakeOQS(), b"x" * 1025)

    def test_live_key_default_and_no_overwrite_on_failure(self):
        # Load actual key persistence functions without importing the model/TUI dependencies.
        tree = ast.parse(Path('main.py').read_text())
        names = {'build_trihybrid_key', 'save_wrapped_key', 'load_data_key', 'get_or_create_key'}
        subset = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names], type_ignores=[])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / '.enc_key'
            scope = dict(hmac=hmac, Optional=__import__('typing').Optional, os=os, tri=tri, storage=storage, KEY_PATH=path,
                         KEY_FLAG_PASSPHRASE=1, _OQS=FakeOQS(), AESGCM=AESGCM,
                         NKEY4_VERSION=2,
                         _hybrid_kek=lambda salt, pw, lane: sc._hkdf((pw or '').encode(), salt, lane, 32),
                         _nkey4_protector=lambda salt, pw, version: sc._hkdf(
                             (pw or 'machine').encode(), salt, b'TRI' if version == 1 else b'nkey4-v2', 32),
                         _atomic_write_private=lambda p, data: (p.write_bytes(data), p.chmod(0o600)),
                         _assert_private_regular=lambda *a: None, _pw_guard=lambda: None,
                         _pw_ok=lambda: None, _pw_fail=lambda: None, SpookyCombinerError=sc.SpookyCombinerError)
            exec(compile(subset, 'main.py', 'exec'), scope)
            scope['save_wrapped_key'](self.payload, 'secret')
            original = path.read_bytes()
            self.assertTrue(original.startswith(b'NKEY4'))
            self.assertEqual(scope['load_data_key']('secret'), self.payload)
            with self.assertRaises(sc.SpookyCombinerError):
                scope['load_data_key']('wrong')
            scope['_pw_ok']()

            salt = os.urandom(16)
            legacy_header = b'NKEY4' + bytes([1, 1]) + salt
            legacy_protector = scope['_hybrid_kek'](salt, 'secret', b'TRI')
            path.write_bytes(legacy_header + tri.create_envelope(
                self.payload, legacy_protector, FakeOQS(), legacy_header
            ))
            path.chmod(0o600)
            self.assertEqual(scope['load_data_key']('secret'), self.payload)
            self.assertEqual(path.read_bytes()[5], 2)
            original = path.read_bytes()

            scope['_OQS'] = None
            with self.assertRaises(sc.SpookyCombinerError):
                scope['save_wrapped_key'](os.urandom(32), 'secret')
            with self.assertRaises(sc.SpookyCombinerError):
                scope['load_data_key']('secret')
            self.assertEqual(path.read_bytes(), original)

            scope['_OQS'] = FakeOQS()
            scope['save_wrapped_key'](self.payload, None)
            self.assertEqual(scope['load_data_key'](), self.payload)


if __name__ == '__main__':
    unittest.main()
