import re
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "lock-requirements.yml"
PROOT_SETUP = Path(__file__).parents[1] / "termux-naza-autosetup" / "setup.sh"
PROOT_BOOT = Path(__file__).parents[1] / "termux-naza-autosetup" / "naza_boot.sh"
PROOT_HEALTH = Path(__file__).parents[1] / "termux-naza-autosetup" / "naza_healthcheck.sh"
NATIVE_SETUP = Path(__file__).parents[1] / "termux-naza-autosetup" / "setup_ubuntu.sh"
RUNNER = Path(__file__).parents[1] / "run_naza.sh"
UNLOCKERS = (
    Path(__file__).parents[1] / "naza_unlock.sh",
    Path(__file__).parents[1] / "termux-naza-autosetup" / "naza_unlock.sh",
)

class CiSupplyChainTests(unittest.TestCase):
    def test_liboqs_archive_is_verified_before_extraction(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        expected = re.search(r'LIBOQS_EXPECTED_SHA256="([0-9a-f]{64})"', workflow)
        self.assertIsNotNone(expected)
        verify_at = workflow.index('sha256sum -c -')
        extract_at = workflow.index('tar -xzf /tmp/liboqs.tar.gz')
        configure_at = workflow.index('cmake -S /tmp/liboqs-src')
        self.assertLess(verify_at, extract_at)
        self.assertLess(verify_at, configure_at)

    def test_workflow_change_triggers_lock_job(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("- .github/workflows/lock-requirements.yml", workflow)

    def test_lock_artifacts_receive_independent_provenance(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("id-token: write", workflow)
        self.assertIn("attestations: write", workflow)
        attest_at = workflow.index("uses: actions/attest-build-provenance@00014ed6ed5efc5b1ab7f7f34a39eb55d41aa4f8")
        sign_at = workflow.index("python /tmp/pq_sign_lock.py")
        upload_at = workflow.index("uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02")
        self.assertLess(sign_at, attest_at)
        self.assertLess(attest_at, upload_at)
        for artifact in ("requirements.txt", "lock.manifest.json", "lock.manifest.pqsig", "pq_pubkey.b64"):
            self.assertIn(artifact, workflow[attest_at:upload_at])

    def test_ci_bootstrap_and_actions_are_immutable(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("python:3.12-slim@sha256:", workflow)
        self.assertIn("pip install --require-hashes -r bootstrap-requirements.txt", workflow)
        self.assertNotIn("pip install --upgrade pip", workflow)
        self.assertNotRegex(workflow, r"uses:\s+[^\s]+@v\d+(?:\s|$)")
        self.assertNotIn("ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION", workflow)

    def test_proot_boundary_is_hardened(self):
        setup = PROOT_SETUP.read_text(encoding="utf-8")
        boot = PROOT_BOOT.read_text(encoding="utf-8")
        self.assertIn("runuser -u sudouser -- env", setup)
        self.assertNotIn("su - sudouser -c", setup)
        self.assertIn("mktemp -d /tmp/naza-install.XXXXXX", setup)
        self.assertIn('pip install --require-hashes -r "$APP_DIR/bootstrap-requirements.txt"', setup)
        self.assertNotIn('pip install -r "$APP_DIR/requirements.in"', setup)
        self.assertNotIn("--shared-tmp", boot)
        self.assertGreaterEqual(boot.count("--isolated"), 3)
        self.assertIn("ulimit -c 0", boot)
        self.assertIn("ulimit -n 256", boot)
        self.assertNotIn('--bind "$HOME_T/.naza:', boot)
        self.assertNotIn('mktemp "$HOME/.naza/.unlock.token.XXXXXX"', boot)
        self.assertIn('NAZA_TOKEN_OUTPUT=stdout bash "$UNLOCK_SH"', boot)
        self.assertIn("exec 9< <(NAZA_TOKEN_OUTPUT", boot)
        self.assertIn('export NAZA_UNLOCK_FD=9', boot)
        self.assertNotIn("HOST_TOKEN=", boot)
        self.assertNotIn("TOKEN_VALUE=", boot)
        self.assertIn('[ ! -L "$UNLOCK_SH" ]', boot)

    def test_keystore_policy_is_checked_at_setup_and_use(self):
        setup = PROOT_SETUP.read_text(encoding="utf-8")
        self.assertIn("termux-keystore list -d", setup)
        self.assertIn('awk -v alias="$KEY_ALIAS"', setup)
        self.assertIn('"required"[[:space:]]*:[[:space:]]*true', setup)
        self.assertIn('"algorithm"[[:space:]]*:[[:space:]]*"RSA"', setup)
        for path in UNLOCKERS:
            script = path.read_text(encoding="utf-8")
            self.assertIn("termux-keystore list -d", script)
            self.assertIn('awk -v alias="$ALIAS"', script)
            self.assertIn("does not require Android authentication", script)

    def test_deployment_healthcheck_uses_isolated_guest(self):
        setup = PROOT_SETUP.read_text(encoding="utf-8")
        check = PROOT_HEALTH.read_text(encoding="utf-8")
        self.assertIn("naza_healthcheck.sh", setup)
        self.assertIn('bash "$HOME/.naza/naza_healthcheck.sh"', setup)
        self.assertIn("--isolated --user sudouser", check)
        self.assertIn("naza_crypto_preflight.py", check)
        self.assertIn("8#$mode & 8#022", check)

    def test_native_installer_rejects_unsafe_targets_and_unlocked_fallbacks(self):
        setup = NATIVE_SETUP.read_text(encoding="utf-8")
        self.assertIn('NAZA_APP_DIR must be a child of HOME', setup)
        self.assertIn('NAZA_REPO_URL must be an HTTPS GitHub repository URL', setup)
        self.assertIn('pip install --require-hashes -r "$APP_DIR/bootstrap-requirements.txt"', setup)
        self.assertNotIn('pip install -r "$APP_DIR/requirements.in"', setup)
        self.assertIn('remote get-url origin', setup)
        self.assertIn('rev-parse FETCH_HEAD', setup)

    def test_unlock_helpers_use_atomic_private_files(self):
        for path in UNLOCKERS:
            script = path.read_text(encoding="utf-8")
            self.assertIn("umask 077", script)
            self.assertIn('mktemp "$NAZA_DIR/.challenge.XXXXXX"', script)
            self.assertIn('mktemp "$NAZA_DIR/.unlock.token.XXXXXX"', script)
            self.assertIn('grep -Eq \'^[0-9a-f]{64}$\'', script)
            self.assertIn('[ ! -L "$NAZA_DIR" ]', script)
            self.assertIn('[ -e "$CHALLENGE" ] || [ -L "$CHALLENGE" ]', script)
            self.assertNotIn('rm -f -- "$CHALLENGE"', script)

    def test_runtime_environment_is_sanitized(self):
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("unset LD_PRELOAD PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP", runner)
        self.assertIn('export LD_LIBRARY_PATH="$OQS_PREFIX/lib"', runner)
        self.assertNotIn("${NAZA_VENV:-", runner)
        self.assertNotIn("${OQS_INSTALL_PATH:-", runner)
        self.assertIn("safe_runtime_file", runner)
        self.assertIn("8#022", runner)
        self.assertIn('naza_crypto_preflight.py', runner)
        self.assertIn('export NAZA_REQUIRE_PROCESS_HARDENING=1', runner)

    def test_crypto_runtime_pins_include_security_fixes_and_argon2(self):
        repair = (Path(__file__).parents[1] / "install-native-termux-repair.sh").read_text(encoding="utf-8")
        self.assertIn('CRYPTO_VERSION="46.0.7"', repair)
        self.assertIn('ARGON2_VERSION="25.1.0"', repair)
        self.assertIn('ARGON2_BINDINGS_VERSION="25.1.0"', repair)
        preflight = (Path(__file__).parents[1] / "naza_crypto_preflight.py").read_text(encoding="utf-8")
        self.assertIn('"cryptography": "46.0.7"', preflight)
        self.assertIn('"argon2-cffi": "25.1.0"', preflight)
        self.assertIn('openssl_version_text()', preflight)

if __name__ == "__main__":
    unittest.main()
