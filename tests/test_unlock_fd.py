import ast
import os
from pathlib import Path
import re
import unittest
from typing import Optional


MAIN = Path(__file__).resolve().parents[1] / "main.py"


def fd_scope():
    tree = ast.parse(MAIN.read_text(encoding="utf-8"))
    fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_read_unlock_fd")
    scope = {
        "os": os, "re": re, "Optional": Optional,
        "_UNLOCK_FD_READ": False, "_UNLOCK_FD_TOKEN": None,
    }
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "main.py", "exec"), scope)
    return scope


class UnlockDescriptorTests(unittest.TestCase):
    def _run(self, payload):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, payload)
        finally:
            os.close(write_fd)
        scope = fd_scope()
        old = os.environ.get("NAZA_UNLOCK_FD")
        os.environ["NAZA_UNLOCK_FD"] = str(read_fd)
        try:
            first = scope["_read_unlock_fd"]()
            second = scope["_read_unlock_fd"]()
            return first, second
        finally:
            if old is None:
                os.environ.pop("NAZA_UNLOCK_FD", None)
            else:
                os.environ["NAZA_UNLOCK_FD"] = old

    def test_valid_token_is_consumed_once_and_cached(self):
        token = b"a" * 64 + b"\n"
        self.assertEqual(self._run(token), ("a" * 64, "a" * 64))

    def test_malformed_or_oversized_token_fails_closed(self):
        self.assertEqual(self._run(b"not-a-token\n"), (None, None))
        self.assertEqual(self._run(b"a" * 130), (None, None))


if __name__ == "__main__":
    unittest.main()
