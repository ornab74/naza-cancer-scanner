#!/data/data/com.termux/files/usr/bin/bash
# Required biometric/keystore unlock on Termux, then launch SpookyNaza in Ubuntu proot.
set -euo pipefail
umask 077
HOME_T="${HOME:-/data/data/com.termux/files/home}"
UNLOCK_SH="$HOME_T/.naza/naza_unlock.sh"

proot-distro login --help 2>&1 | grep -q -- '--isolated' || {
  echo "ERROR: proot-distro lacks required --isolated mode" >&2; exit 1;
}

[ -x "$UNLOCK_SH" ] && [ ! -L "$UNLOCK_SH" ] || { echo "ERROR: unsafe or missing $UNLOCK_SH" >&2; exit 1; }
[ "$(stat -c %u "$UNLOCK_SH")" = "$(id -u)" ] || { echo "ERROR: unlock helper has wrong owner" >&2; exit 1; }
chmod 700 "$UNLOCK_SH"
# Preserve interactive stdin and stream directly from the authenticated helper.
# Python treats descriptor 9 as mandatory, so helper failure/EOF cannot fall back.
exec 9< <(NAZA_TOKEN_OUTPUT=stdout bash "$UNLOCK_SH")

proot-distro login ubuntu --isolated --user sudouser \
  -- bash -lc '
    set -eu
    umask 077
    ulimit -c 0
    ulimit -n 256
    cd /home/sudouser/naza
    export NAZA_UNLOCK_FD=9
    export NAZA_CRYPTO_MODE=tri
    export OQS_INSTALL_PATH=/home/sudouser/.local/liboqs-0.14.0
    unset LD_PRELOAD PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP
    export LD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib"
    export TERM="${TERM:-xterm-256color}" LANG=C.UTF-8 PYTHONUNBUFFERED=1
    exec ./run_naza.sh
  '
