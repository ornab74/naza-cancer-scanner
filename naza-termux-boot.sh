#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
HOME="${HOME:-/data/data/com.termux/files/home}"
export LD_PRELOAD="$PREFIX/lib/libtermux-exec.so"

NAZA_DIR="$HOME/naza"
UNLOCK="$NAZA_DIR/naza_unlock.sh"
RUN="$NAZA_DIR/run_naza.sh"

[ -x "$UNLOCK" ] || { echo "ERROR: Gate 3 helper missing: $UNLOCK" >&2; exit 1; }
[ -x "$RUN" ] || { echo "ERROR: launcher missing: $RUN" >&2; exit 1; }

while true; do
    clear 2>/dev/null || true
    cat <<'MENU'
╔══════════════════════════════════════════╗
║              NAZA SECURITY               ║
╠══════════════════════════════════════════╣
║       Android Keystore Gate 3            ║
║                                          ║
║  Unlock/authenticate the phone, then:    ║
║                                          ║
║  U = authorize + start Naza              ║
║  Q = quit                                ║
╚══════════════════════════════════════════╝
MENU
    printf '\nSelect [U/Q]: '
    IFS= read -r answer || exit 0
    case "$answer" in
        U|u)
            "$UNLOCK" || { echo "Gate 3 authorization failed." >&2; read -r -p "Press Enter..." _ || true; continue; }
            exec "$RUN"
            ;;
        Q|q) exit 0 ;;
        *) echo "Invalid selection."; sleep 1 ;;
    esac
done
