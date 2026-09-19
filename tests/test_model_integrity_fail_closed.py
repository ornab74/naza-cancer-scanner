import ast
import hashlib
import hmac
import os
import stat as statmod
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
MAIN = ROOT / "main.py"


class ModelIntegrityFailClosedTests(unittest.TestCase):
    def test_no_continue_anyway_bypass_text(self):
        source = MAIN.read_text(encoding="utf-8")
        self.assertNotIn("Continue and encrypt anyway?", source)
        self.assertNotIn("File is kept; you can still encrypt and use it.", source)

    def test_llama_loader_verifies_before_constructor(self):
        source = MAIN.read_text(encoding="utf-8")
        tree = ast.parse(source)
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "load_llama_model_blocking")
        calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
        verify = next(i for i, c in enumerate(calls) if isinstance(c.func, ast.Name) and c.func.id == "verify_model_integrity")
        llama = next(i for i, c in enumerate(calls) if isinstance(c.func, ast.Name) and c.func.id == "Llama")
        self.assertLess(verify, llama)

    def test_integrity_helper_rejects_mismatch(self):
        source = MAIN.read_text(encoding="utf-8")
        tree = ast.parse(source)
        wanted = {"sha256_file", "verify_model_integrity", "_is_symlink"}
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
        ns = {"Path": Path, "hashlib": hashlib, "hmac": hmac, "os": __import__("os"), "statmod": statmod, "EXPECTED_HASH": "0" * 64}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "main.py", "exec"), ns)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "model.gguf"
            p.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                ns["verify_model_integrity"](p, "0" * 64)

    def test_sensitive_artifact_rejects_fifo(self):
        source = MAIN.read_text(encoding="utf-8")
        tree = ast.parse(source)
        wanted = {"_is_symlink", "_assert_private_regular"}
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
        ns = {"Path": Path, "os": os, "statmod": statmod}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "main.py", "exec"), ns)
        with tempfile.TemporaryDirectory() as td:
            fifo = Path(td) / "key.fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(RuntimeError, "not a regular file"):
                ns["_assert_private_regular"](fifo, "key file")

    def test_crypto_outputs_use_atomic_no_follow_writes(self):
        source = MAIN.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for name in ("encrypt_file", "decrypt_file"):
            fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
            calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
            self.assertTrue(any(isinstance(c.func, ast.Name) and c.func.id == "_atomic_write_private" for c in calls))
            self.assertFalse(any(isinstance(c.func, ast.Attribute) and c.func.attr == "write_bytes" for c in calls))

    def test_key_initialization_has_no_implicit_machine_only_fallback(self):
        source = MAIN.read_text(encoding="utf-8")
        tree = ast.parse(source)
        main_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        calls = [n for n in ast.walk(main_fn) if isinstance(n, ast.Call)]
        self.assertFalse(any(isinstance(c.func, ast.Name) and c.func.id == "get_or_create_key" for c in calls))
        ensure_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "ensure_key_interactive")
        self.assertIn("if opt == '1'", ast.unparse(ensure_fn))
        self.assertIn("if not pw or pw != pw2", ast.unparse(ensure_fn))

    def test_unlock_token_cleanup_never_follows_symlinks(self):
        source = MAIN.read_text(encoding="utf-8")
        self.assertIn("UNLOCK_MAX_AGE = 30.0", source)
        self.assertIn('os.environ.pop("NAZA_UNLOCK_FD", "")', source)
        self.assertIn("PR_SET_DUMPABLE", source)
        self.assertIn("Could not enforce non-dumpable process policy", source)
        self.assertIn("PR_SET_NO_NEW_PRIVS", source)
        self.assertIn("Required streamed biometric authorization is missing or malformed", source)
        tree = ast.parse(source)
        consume = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "consume_unlock_token")
        calls = [n for n in ast.walk(consume) if isinstance(n, ast.Call)]
        self.assertFalse(any(isinstance(c.func, ast.Attribute) and c.func.attr in {"write_text", "write_bytes", "open"} for c in calls))
        self.assertTrue(any(isinstance(c.func, ast.Attribute) and c.func.attr == "unlink" for c in calls))

        read = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "read_unlock_token")
        rendered = ast.unparse(read)
        self.assertIn("statmod.S_ISREG", rendered)
        self.assertIn("st.st_uid != os.geteuid()", rendered)
        self.assertIn("age < 0", rendered)

    def test_download_and_export_fail_closed(self):
        source = MAIN.read_text(encoding="utf-8")
        tree = ast.parse(source)
        download = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "download_model_httpx")
        rendered = ast.unparse(download)
        self.assertIn("httpx.Timeout(300.0, connect=30.0)", rendered)
        self.assertIn("r.url.scheme != 'https'", rendered)
        self.assertIn("done > MAX_MODEL_DOWNLOAD", rendered)

        scanner = next(n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "road_scanner_flow")
        calls = [n for n in ast.walk(scanner) if isinstance(n, ast.Call)]
        self.assertTrue(any(isinstance(c.func, ast.Name) and c.func.id == "_atomic_write_private" for c in calls))
        self.assertFalse(any(isinstance(c.func, ast.Attribute) and c.func.attr == "write_text" for c in calls))

    def test_closed_input_does_not_spin(self):
        source = MAIN.read_text(encoding="utf-8")
        tree = ast.parse(source)
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "read_menu_choice")
        rendered = ast.unparse(fn)
        self.assertIn("except EOFError", rendered)
        self.assertIn("raise SystemExit('Input stream closed')", rendered)

    def test_new_passphrases_have_a_minimum_length(self):
        source = MAIN.read_text(encoding="utf-8")
        tree = ast.parse(source)
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "validate_new_passphrase")
        ns = {"MIN_NEW_PASSPHRASE_LENGTH": 12}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), "main.py", "exec"), ns)
        with self.assertRaises(ValueError):
            ns["validate_new_passphrase"]("short")
        ns["validate_new_passphrase"]("correct horse battery staple")

    def test_failed_model_load_never_overwrites_encrypted_copy(self):
        source = MAIN.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for name in ("chat_session", "road_scanner_flow"):
            fn = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == name)
            rendered = ast.unparse(fn)
            self.assertNotIn("encrypt_file(SESSION_MODEL_PATH, ENCRYPTED_MODEL", rendered)
            self.assertIn("secure_unlink(SESSION_MODEL_PATH)", rendered)

    def test_session_plaintext_uses_scrubbed_private_directory(self):
        source = MAIN.read_text(encoding="utf-8")
        tree = ast.parse(source)
        history = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_history_temp")
        self.assertIn("PRIVATE_TMP_DIR", ast.unparse(history))
        main_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        calls = [n for n in ast.walk(main_fn) if isinstance(n, ast.Call)]
        self.assertTrue(any(isinstance(c.func, ast.Name) and c.func.id == "cleanup_private_temps" for c in calls))

    def test_existing_history_is_authenticated_at_startup(self):
        source = MAIN.read_text(encoding="utf-8")
        tree = ast.parse(source)
        init_db = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "init_db")
        rendered = ast.unparse(init_db)
        self.assertIn("verify_file_mac(DB_PATH, key)", rendered)
        self.assertIn("aes_decrypt(storage.read_private(DB_PATH), key)", rendered)
        main_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        self.assertIn("Encrypted history authentication failed", ast.unparse(main_fn))


if __name__ == "__main__":
    unittest.main()
