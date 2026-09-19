#!/data/data/com.termux/files/usr/bin/bash
# Required Termux keystore -> Ubuntu proot -> SpookyNaza + pinned liboqs.
set -euo pipefail
umask 077

NAZA_REF="${NAZA_REF:-main}"
REPO_URL="${NAZA_REPO_URL:-https://github.com/ornab74/naza.git}"
KEY_ALIAS="${NAZA_KEYSTORE_ALIAS:-naza-unlock}"
HERE="$(cd "$(dirname "$0")" && pwd)"

fail() { echo "ERROR: $*" >&2; exit 1; }

[[ "$KEY_ALIAS" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || fail "invalid keystore alias"
[[ "$REPO_URL" =~ ^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+$ ]] || \
  fail "NAZA_REPO_URL must be an HTTPS GitHub repository URL"
[[ "$NAZA_REF" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$ ]] || fail "invalid NAZA_REF"
[[ "$NAZA_REF" != *..* && "$NAZA_REF" != *//* && "$NAZA_REF" != *@\{* ]] || fail "unsafe NAZA_REF"

printf '\n==> Updating Termux and installing required host packages\n'
pkg update -y
pkg install -y git curl coreutils proot-distro termux-api xxd

command -v termux-keystore >/dev/null 2>&1 || \
  fail "termux-keystore is unavailable. Install the Termux:API Android companion app, then rerun this installer."
command -v termux-fingerprint >/dev/null 2>&1 || \
  fail "termux-fingerprint is unavailable. Install the Termux:API Android companion app, then rerun this installer."
proot-distro login --help 2>&1 | grep -q -- '--isolated' || \
  fail "installed proot-distro does not support required --isolated mode"

printf '\n==> Enforcing required Android/Termux keystore key: %s\n' "$KEY_ALIAS"
KEY_LIST="$(termux-keystore list 2>/dev/null || true)"
if ! printf '%s\n' "$KEY_LIST" | grep -Fq "$KEY_ALIAS"; then
  termux-keystore generate "$KEY_ALIAS" -a RSA -s 2048 -u 10 || \
    fail "could not generate required Termux keystore alias '$KEY_ALIAS'"
fi
KEY_LIST="$(termux-keystore list 2>/dev/null || true)"
printf '%s\n' "$KEY_LIST" | grep -Fq "$KEY_ALIAS" || \
  fail "required Termux keystore alias '$KEY_ALIAS' was not found after generation"
KEY_DETAIL="$(termux-keystore list -d 2>/dev/null)" || fail "could not inspect keystore properties"
KEY_RECORD="$(printf '%s\n' "$KEY_DETAIL" | awk -v alias="$KEY_ALIAS" '
  BEGIN { RS="\\\"alias\\\"[[:space:]]*:[[:space:]]*" }
  index($0, "\"" alias "\"") == 1 { print; found=1; exit }
  END { if (!found) exit 1 }
')" || fail "could not isolate detailed metadata for keystore alias '$KEY_ALIAS'"
printf '%s\n' "$KEY_RECORD" | grep -Eq '"algorithm"[[:space:]]*:[[:space:]]*"RSA"' || \
  fail "keystore alias must use RSA"
printf '%s\n' "$KEY_RECORD" | grep -Eq '"size"[[:space:]]*:[[:space:]]*2048' || \
  fail "keystore alias must use a 2048-bit key"
printf '%s\n' "$KEY_RECORD" | grep -Eq '"required"[[:space:]]*:[[:space:]]*true' || \
  fail "keystore alias is not protected by Android user authentication"
printf '%s\n' "$KEY_RECORD" | grep -Eq '"enforced_by_secure_hardware"[[:space:]]*:[[:space:]]*true' || \
  fail "Android does not report hardware-enforced authentication for this key"
echo "Required keystore alias verified: $KEY_ALIAS"

mkdir -p "$HOME/.naza"
chmod 700 "$HOME/.naza"
for helper in naza_unlock.sh naza_boot.sh naza_healthcheck.sh; do
  [ -f "$HERE/$helper" ] || fail "missing installer helper: $HERE/$helper"
  cp "$HERE/$helper" "$HOME/.naza/$helper"
  chmod 700 "$HOME/.naza/$helper"
done

printf '\n==> Installing Ubuntu proot if needed\n'
if proot-distro login ubuntu -- true >/dev/null 2>&1; then
  echo "Ubuntu proot already present; reusing it."
else
  proot-distro install ubuntu
fi
alias naza-health='bash "$HOME/.naza/naza_healthcheck.sh"'

export PROOT_TMP_DIR="$HOME/tmp"
mkdir -p "$PROOT_TMP_DIR"

printf '\n==> Installing SpookyNaza + pinned liboqs inside Ubuntu\n'
proot-distro login ubuntu --isolated -- env NAZA_REF="$NAZA_REF" NAZA_REPO_URL="$REPO_URL" bash <<'PROOT_EOF'
set -euo pipefail
umask 077
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y \
  sudo git curl ca-certificates build-essential cmake ninja-build pkg-config libssl-dev \
  python3 python3-pip python3-venv python3-dev

id -u sudouser >/dev/null 2>&1 || adduser --disabled-password --gecos "" sudouser

INSTALL_DIR="$(mktemp -d /tmp/naza-install.XXXXXX)"
INSTALL_SCRIPT="$INSTALL_DIR/install.sh"
trap 'rm -rf -- "$INSTALL_DIR"' EXIT
cat > "$INSTALL_SCRIPT" <<'INNER_EOF'
set -euo pipefail
umask 077
APP_DIR="$HOME/naza"
REPO_URL="${NAZA_REPO_URL:-https://github.com/ornab74/naza.git}"
NAZA_REF="${NAZA_REF:-main}"

if [ -d "$APP_DIR/.git" ]; then
  [ "$(git -C "$APP_DIR" remote get-url origin)" = "$REPO_URL" ] || {
    echo "ERROR: existing checkout origin does not match NAZA_REPO_URL" >&2
    exit 1
  }
  git -C "$APP_DIR" fetch --prune origin "$NAZA_REF"
else
  rm -rf "$APP_DIR"
  git clone "$REPO_URL" "$APP_DIR"
  git -C "$APP_DIR" fetch --prune origin "$NAZA_REF"
fi
# Resolve the requested ref now and detach so the installed tree cannot drift silently.
git -C "$APP_DIR" checkout --detach FETCH_HEAD
[ "$(git -C "$APP_DIR" rev-parse HEAD)" = "$(git -C "$APP_DIR" rev-parse FETCH_HEAD)" ] || {
  echo "ERROR: checkout does not match fetched revision" >&2
  exit 1
}

python3 -m venv "$APP_DIR/venv"
. "$APP_DIR/venv/bin/activate"
[ -f "$APP_DIR/bootstrap-requirements.txt" ] || { echo "ERROR: missing bootstrap lock" >&2; exit 1; }
[ -f "$APP_DIR/requirements.txt" ] || { echo "ERROR: missing application lock" >&2; exit 1; }
python -m pip install --require-hashes -r "$APP_DIR/bootstrap-requirements.txt"
python -m pip install --require-hashes -r "$APP_DIR/requirements.txt"

chmod +x "$APP_DIR/install_liboqs_0.14.0.sh" "$APP_DIR/run_naza.sh"
export PYTHON_BIN="$APP_DIR/venv/bin/python"
PREFIX="$HOME/.local/liboqs-0.14.0" "$APP_DIR/install_liboqs_0.14.0.sh"

export OQS_INSTALL_PATH="$HOME/.local/liboqs-0.14.0"
unset LD_PRELOAD PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP
export LD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib"
export NAZA_CRYPTO_MODE=tri
"$APP_DIR/venv/bin/python" - <<'PY'
import oqs
mechs = set(oqs.get_enabled_kem_mechanisms())
missing = {"ML-KEM-1024", "HQC-256"} - mechs
if mechs != {"ML-KEM-1024", "HQC-256"} or oqs.get_enabled_sig_mechanisms():
    raise SystemExit("Unexpected liboqs algorithms installed")
if missing:
    raise SystemExit("SpookyNaza install failed; missing OQS mechanisms: " + ", ".join(sorted(missing)))
print("SpookyNaza default verified: tri-hybrid NKEY4 + ML-KEM-1024 + HQC-256 + X25519")
PY
INNER_EOF
chmod 700 "$INSTALL_DIR" "$INSTALL_SCRIPT"
chown -R sudouser:sudouser "$INSTALL_DIR"
runuser -u sudouser -- env \
  NAZA_REF="$NAZA_REF" \
  NAZA_REPO_URL="$NAZA_REPO_URL" \
  bash "$INSTALL_SCRIPT"
PROOT_EOF

if ! grep -q '^# === BEGIN NAZA AUTO-START ===$' "$HOME/.bashrc" 2>/dev/null; then
cat >> "$HOME/.bashrc" <<'BASHRC'
# === BEGIN NAZA AUTO-START ===
if [ -z "${NAZA_STARTED:-}" ] && [ "$PWD" = "$HOME" ] && [ -z "${SSH_CLIENT:-}" ] && [ -z "${TMUX:-}" ]; then
    export NAZA_STARTED=1
    if [ -x "$HOME/.naza/naza_boot.sh" ]; then
        bash "$HOME/.naza/naza_boot.sh"
    fi
fi
alias naza='bash "$HOME/.naza/naza_boot.sh"'
alias naza-unlock='bash "$HOME/.naza/naza_unlock.sh"'
alias naza-health='bash "$HOME/.naza/naza_healthcheck.sh"'
# === END NAZA AUTO-START ===
BASHRC
fi

printf '\n==> Running isolated deployment health check\n'
bash "$HOME/.naza/naza_healthcheck.sh"

echo
echo "=============================================================="
echo "Naza installation complete."
echo "Required Termux keystore alias: $KEY_ALIAS"
echo "Default crypto mode: SpookyNaza tri-hybrid (NKEY4)"
echo "Pinned liboqs: 0.14.0, verified before build"
echo "Reopen Termux or run: naza"
echo "Deployment check: naza-health"
echo "=============================================================="
