#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

printf '== forbidden source-tree debris ==\n'
if find . -type f \( -name '*.pyc' -o -name '*.log' -o -name '*.before-*' -o -name '*.pre-*' \) \
    -not -path './.git/*' -not -path './venv-termux/*' -print -quit | grep -q .; then
  echo 'ERROR: generated/recovery debris is present.' >&2
  exit 1
fi
if [ -d models ] || [ -d venv-termux ] || [ -f .enc_key ]; then
  echo 'ERROR: runtime models/venv/secret state must not be in the source tree.' >&2
  exit 1
fi

printf '== shell syntax ==\n'
while IFS= read -r -d '' file; do
  bash -n "$file"
done < <(find . -type f -name '*.sh' -not -path './venv-termux/*' -not -path './.git/*' -print0)

printf '== python syntax ==\n'
python - <<'PY'
from pathlib import Path
files = [
    Path('main.py'), Path('naza_crypto_preflight.py'), Path('naza_storage.py'),
    Path('spooky_combiner.py'), Path('spooky_trihybrid.py'),
    *sorted(Path('tests').glob('*.py')),
]
for path in files:
    compile(path.read_bytes(), str(path), 'exec')
print(f'compiled {len(files)} Python files')
PY

printf '== regression/security tests ==\n'
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python -m unittest discover -s tests -v

printf '== core model pin ==\n'
grep -F 'MODEL_FILE = "llama3-small-Q3_K_M.gguf"' main.py >/dev/null
grep -F 'EXPECTED_HASH = "8e4f4856fb84bafb895f1eb08e6c03e4be613ead2d942f91561aeac742a619aa"' main.py >/dev/null

printf 'verify-tree: PASS\n'
