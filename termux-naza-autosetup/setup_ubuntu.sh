#!/usr/bin/env bash
# Native Ubuntu/Debian installer for SpookyNaza + pinned liboqs.
set -euo pipefail
umask 077

APP_DIR="${NAZA_APP_DIR:-$HOME/naza}"
REPO_URL="${NAZA_REPO_URL:-https://github.com/ornab74/naza.git}"
NAZA_REF="${NAZA_REF:-main}"
VENV_DIR="$APP_DIR/venv"

fail() { echo "ERROR: $*" >&2; exit 1; }
case "$APP_DIR" in
  "$HOME"/*) ;;
  *) fail "NAZA_APP_DIR must be a child of HOME" ;;
esac
[[ "$REPO_URL" =~ ^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+$ ]] || \
  fail "NAZA_REPO_URL must be an HTTPS GitHub repository URL"
[[ "$NAZA_REF" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$ ]] || fail "invalid NAZA_REF"
[[ "$NAZA_REF" != *..* && "$NAZA_REF" != *//* && "$NAZA_REF" != *@\{* ]] || fail "unsafe NAZA_REF"

sudo apt update
sudo apt install -y \
  git curl ca-certificates build-essential cmake ninja-build pkg-config libssl-dev \
  python3 python3-pip python3-venv python3-dev

if [ -d "$APP_DIR/.git" ]; then
  [ "$(git -C "$APP_DIR" remote get-url origin)" = "$REPO_URL" ] || \
    fail "existing checkout origin does not match NAZA_REPO_URL"
  git -C "$APP_DIR" fetch --prune origin "$NAZA_REF"
else
  rm -rf "$APP_DIR"
  git clone "$REPO_URL" "$APP_DIR"
  git -C "$APP_DIR" fetch --prune origin "$NAZA_REF"
fi
git -C "$APP_DIR" checkout --detach FETCH_HEAD
[ "$(git -C "$APP_DIR" rev-parse HEAD)" = "$(git -C "$APP_DIR" rev-parse FETCH_HEAD)" ] || \
  fail "checkout does not match fetched revision"

python3 -m venv "$VENV_DIR"
. "$VENV_DIR/bin/activate"
[ -f "$APP_DIR/bootstrap-requirements.txt" ] || fail "missing bootstrap lock"
[ -f "$APP_DIR/requirements.txt" ] || fail "missing application lock"
python -m pip install --require-hashes -r "$APP_DIR/bootstrap-requirements.txt"
python -m pip install --require-hashes -r "$APP_DIR/requirements.txt"

chmod +x "$APP_DIR/install_liboqs_0.14.0.sh" "$APP_DIR/run_naza.sh"
export PYTHON_BIN="$VENV_DIR/bin/python"
PREFIX="$HOME/.local/liboqs-0.14.0" "$APP_DIR/install_liboqs_0.14.0.sh"

export OQS_INSTALL_PATH="$HOME/.local/liboqs-0.14.0"
unset LD_PRELOAD PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP
export LD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib"
export NAZA_CRYPTO_MODE=tri
"$VENV_DIR/bin/python" - <<'PY'
import oqs
mechs = set(oqs.get_enabled_kem_mechanisms())
missing = {"ML-KEM-1024", "HQC-256"} - mechs
if mechs != {"ML-KEM-1024", "HQC-256"} or oqs.get_enabled_sig_mechanisms():
    raise SystemExit("Unexpected liboqs algorithms installed")
if missing:
    raise SystemExit("SpookyNaza install failed; missing OQS mechanisms: " + ", ".join(sorted(missing)))
print("SpookyNaza default verified: tri-hybrid NKEY4 + ML-KEM-1024 + HQC-256 + X25519")
PY

echo
echo "Installation complete. Start Naza with:"
echo "  $APP_DIR/run_naza.sh"
