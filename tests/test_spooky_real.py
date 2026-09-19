"""Run envelope regression tests using the installed real liboqs backend."""
import unittest
from unittest.mock import patch
try:
    import oqs
except ImportError:
    oqs = None
import spooky_combiner as sc
import test_spooky_trihybrid as tests
import test_naza_rotation as rotation_tests

@unittest.skipIf(oqs is None, 'real liboqs backend is not installed')
class RealLibOQSAvailability(unittest.TestCase):
    def test_backend_available(self):
        self.assertIsNotNone(oqs)

if __name__ == '__main__':
    print('liboqs:', oqs.oqs_version())
    print('Enabled KEMs:', oqs.get_enabled_kem_mechanisms())
    assert oqs.oqs_version() == '0.14.0'
    assert sc.status(oqs).ready
    print('Spooky self-test:', sc.self_test(oqs))
    with patch.object(tests, 'FakeOQS', lambda: oqs), patch.object(rotation_tests, 'FakeOQS', lambda: oqs):
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(tests.TriHybridTests),
                                unittest.defaultTestLoader.loadTestsFromTestCase(rotation_tests.RotationTests)])
        )
    raise SystemExit(not result.wasSuccessful())
