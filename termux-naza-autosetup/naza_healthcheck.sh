#!/data/data/com.termux/files/usr/bin/bash
# Read-only host/guest deployment validation. Safe to run after upgrades/recovery.
set -euo pipefail
umask 077

fail() { echo "ERROR: $*" >&2; exit 1; }
ALIAS="${NAZA_KEYSTORE_ALIAS:-naza-unlock}"
[[ "$ALIAS" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || fail "invalid keystore alias"
command -v proot-distro >/dev/null 2>&1 || fail "proot-distro is unavailable"
command -v termux-keystore >/dev/null 2>&1 || fail "termux-keystore is unavailable"
proot-distro login --help 2>&1 | grep -q -- '--isolated' || fail "--isolated mode is unavailable"

DETAIL="$(termux-keystore list -d 2>/dev/null)" || fail "cannot inspect Android Keystore"
RECORD="$(printf '%s\n' "$DETAIL" | awk -v alias="$ALIAS" '
  BEGIN { RS="\\\"alias\\\"[[:space:]]*:[[:space:]]*" }
  index($0, "\"" alias "\"") == 1 { print; found=1; exit }
  END { if (!found) exit 1 }
')" || fail "required keystore alias is missing"
printf '%s\n' "$RECORD" | grep -Eq '"required"[[:space:]]*:[[:space:]]*true' || \
  fail "keystore key does not require Android authentication"
printf '%s\n' "$RECORD" | grep -Eq '"enforced_by_secure_hardware"[[:space:]]*:[[:space:]]*true' || \
  fail "keystore authentication is not hardware-enforced"

proot-distro login ubuntu --isolated --user sudouser -- bash -c '
  set -eu
  umask 077
  app="$HOME/naza"
  test -d "$app"
  test -x "$app/run_naza.sh"
  test -x "$app/venv/bin/python"
  test -f "$app/naza_crypto_preflight.py"
  owner="$(stat -c %u "$app")"
  test "$owner" = "$(id -u)"
  mode="$(stat -c %a "$app")"
  test $((8#$mode & 8#022)) -eq 0
  export OQS_INSTALL_PATH="$HOME/.local/liboqs-0.14.0"
  unset LD_PRELOAD PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP
  export LD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib"
  cd "$app"
  "$app/venv/bin/python" "$app/naza_crypto_preflight.py"
' || fail "isolated guest validation failed"

echo "Naza isolated deployment health check: PASS"
