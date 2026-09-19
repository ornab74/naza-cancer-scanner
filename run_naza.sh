#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
HOME="${HOME:-/data/data/com.termux/files/home}"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$APP_DIR/venv-termux"
OQS_PREFIX="$HOME/.local/liboqs-0.14.0"
TERMUX_EXEC="$PREFIX/lib/libtermux-exec.so"

safe_runtime_file() {
  local path="$1" resolved owner mode
  resolved="$(readlink -f -- "$path")" || return 1
  [ -f "$resolved" ] || return 1
  owner="$(stat -c %u "$resolved")" || return 1
  mode="$(stat -c %a "$resolved")" || return 1
  [ "$owner" = "$(id -u)" ] || [ "$owner" = "0" ] || return 1
  [ $((8#$mode & 8#022)) -eq 0 ] || return 1
}

[ -x "$VENV_DIR/bin/python" ] || { echo "ERROR: Naza virtual environment not found at $VENV_DIR" >&2; exit 1; }
safe_runtime_file "$VENV_DIR/bin/python" || { echo "ERROR: Python runtime has unsafe ownership or permissions" >&2; exit 1; }
OQS_LIBRARY="$(find "$OQS_PREFIX/lib" -maxdepth 1 -name 'liboqs.so*' -print -quit 2>/dev/null || true)"
[ -n "$OQS_LIBRARY" ] && safe_runtime_file "$OQS_LIBRARY" || { echo "ERROR: pinned liboqs backend not found or unsafe at $OQS_PREFIX" >&2; exit 1; }
[ -f "$TERMUX_EXEC" ] && safe_runtime_file "$TERMUX_EXEC" || { echo "ERROR: Termux execution hook missing or unsafe: $TERMUX_EXEC" >&2; exit 1; }

# Remove inherited loader/Python injection state, then add back only the known
# Termux execution hook required by native Android executables.
unset LD_PRELOAD PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP
export LD_PRELOAD="$TERMUX_EXEC"
export VIRTUAL_ENV="$VENV_DIR"
export PATH="$VENV_DIR/bin:$PATH"
export OQS_INSTALL_PATH="$OQS_PREFIX"
export LD_LIBRARY_PATH="$OQS_PREFIX/lib"
export NAZA_CRYPTO_MODE="tri"
export NAZA_REQUIRE_PROCESS_HARDENING=1
export TERM="${TERM:-xterm-256color}"
export LANG="${LANG:-C.UTF-8}"
export PYTHONUNBUFFERED=1
ulimit -c 0 2>/dev/null || true

cd "$APP_DIR"
"$VENV_DIR/bin/python" "$APP_DIR/naza_crypto_preflight.py"
exec "$VENV_DIR/bin/python" -u "$APP_DIR/main.py" "$@"
