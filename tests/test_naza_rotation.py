import ast
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile
import unittest
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import naza_storage as storage
import spooky_combiner as sc
import spooky_trihybrid as tri
from test_spooky_combiner import FakeOQS


class RotationTests(unittest.TestCase):
    def setUp(self):
        source = Path(__file__).with_name('main.py')
        if not source.exists():
            source = Path(__file__).resolve().parents[1] / 'main.py'
        tree = ast.parse(source.read_text())
        names = {'build_trihybrid_key', 'rotate_data_key', 'rotation_targets', 'aes_encrypt', 'aes_decrypt'}
        subset = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names], type_ignores=[])
        self.temp = tempfile.TemporaryDirectory()
        self.cwd = Path.cwd()
        os.chdir(self.temp.name)
        self.ns = dict(Optional=Optional, Path=Path, os=os, hmac=hmac, hashlib=hashlib, json=json,
            AESGCM=AESGCM, tri=tri, storage=storage, _OQS=FakeOQS(), KEY_FLAG_PASSPHRASE=1,
            NKEY4_VERSION=2,
            ENCRYPTED_MODEL=Path('model.aes'), DB_PATH=Path('db.aes'), KEY_PATH=Path('.enc_key'),
            LOCK_PATH=Path('lock.json'), MAC_SUFFIX='.mac',
            _hybrid_kek=lambda salt, pw, lane: sc._hkdf((pw or '').encode(), salt, lane, 32),
            _nkey4_protector=lambda salt, pw, version: sc._hkdf((pw or 'machine').encode(), salt, b'nkey4-v2', 32),
            _mac_key=lambda key: sc._hkdf(key, b'salt', b'mac', 32),
            _assert_private_regular=lambda path, label: storage.regular(path))
        exec(compile(subset, 'main.py', 'exec'), self.ns)
        self.old = os.urandom(32)
        self.ns['KEY_PATH'].write_bytes(b'original envelope')
        self.ns['KEY_PATH'].chmod(0o600)
        for path in (self.ns['ENCRYPTED_MODEL'], self.ns['DB_PATH']):
            path.write_bytes(self.ns['aes_encrypt'](b'private ' + path.name.encode(), self.old))
            path.chmod(0o600)
        self.before = {p: p.read_bytes() for p in Path('.').iterdir()}

    def tearDown(self):
        os.chdir(self.cwd)
        self.temp.cleanup()

    def test_rotation_updates_files_key_and_macs(self):
        key = self.ns['rotate_data_key'](self.old, 'gate')
        for path in (self.ns['ENCRYPTED_MODEL'], self.ns['DB_PATH']):
            self.assertEqual(self.ns['aes_decrypt'](path.read_bytes(), key), b'private ' + path.name.encode())
            expected = hmac.new(self.ns['_mac_key'](key), path.read_bytes(), hashlib.sha256).digest()
            self.assertEqual(Path(str(path) + '.mac').read_bytes(), expected)
        blob = self.ns['KEY_PATH'].read_bytes()
        protector = self.ns['_nkey4_protector'](blob[7:23], 'gate', blob[5])
        self.assertEqual(tri.open_envelope(blob[23:], protector, self.ns['_OQS'], blob[:23]), key)
        self.assertFalse(Path('.naza-rotation').exists())

    def test_corrupt_second_file_preserves_key_and_first_file(self):
        self.ns['DB_PATH'].write_bytes(b'corrupted')
        with self.assertRaises(Exception):
            self.ns['rotate_data_key'](self.old, 'gate')
        for name in ('KEY_PATH', 'ENCRYPTED_MODEL'):
            path = self.ns[name]
            self.assertEqual(path.read_bytes(), self.before[path])
        self.assertFalse(Path('.naza-rotation').exists())

    def test_bad_mac_aborts_before_replacing_data(self):
        Path('model.aes.mac').write_bytes(b'bad tag')
        Path('model.aes.mac').chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'MAC'):
            self.ns['rotate_data_key'](self.old, 'gate')
        for path, content in self.before.items():
            self.assertEqual(path.read_bytes(), content)


if __name__ == '__main__':
    unittest.main()
