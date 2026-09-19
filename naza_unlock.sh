#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
HOME_T="${HOME:-/data/data/com.termux/files/home}"
NAZA_DIR="$HOME_T/.naza"
KEYSTORE="$PREFIX/bin/termux-keystore"
ALIAS="${NAZA_KEYSTORE_ALIAS:-naza-unlock}"
SIGN_ALGO="SHA256withRSA"
OUTPUT_MODE="${NAZA_TOKEN_OUTPUT:-file}"
CHALLENGE="$NAZA_DIR/challenge"
TOKEN="$NAZA_DIR/unlock.token"

export LD_PRELOAD="$PREFIX/lib/libtermux-exec.so"

CHALLENGE_TMP=""
SIGNATURE_TMP=""
TOKEN_TMP=""
cleanup() {
    [ -z "$CHALLENGE_TMP" ] || rm -f -- "$CHALLENGE_TMP"
    [ -z "$SIGNATURE_TMP" ] || rm -f -- "$SIGNATURE_TMP"
    [ -z "$TOKEN_TMP" ] || rm -f -- "$TOKEN_TMP"
}
trap cleanup EXIT HUP INT TERM

die() {
    echo "ERROR: $*" >&2
    exit 1
}

[[ "$ALIAS" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "invalid keystore alias"
[ "$OUTPUT_MODE" = "file" ] || [ "$OUTPUT_MODE" = "stdout" ] || die "invalid token output mode"
[ -x "$KEYSTORE" ] || die "termux-keystore unavailable"

mkdir -p "$NAZA_DIR"
[ ! -L "$NAZA_DIR" ] || die ".naza is a symbolic link"
[ "$(stat -c %u "$NAZA_DIR")" = "$(id -u)" ] || die ".naza has the wrong owner"
chmod 700 "$NAZA_DIR"

# Fail closed unless the Android Keystore key is the expected Gate-3 key.
KEY_DETAIL="$(termux-keystore list -d 2>/dev/null)" || die "cannot inspect Android Keystore"
KEY_RECORD="$(printf '%s\n' "$KEY_DETAIL" | awk -v alias="$ALIAS" '
  BEGIN { RS="\\\"alias\\\"[[:space:]]*:[[:space:]]*\"" }
  index($0, "\"" alias "\"") == 1 { print; found=1; exit }
  END { if (!found) exit 1 }
')" || die "Android Keystore alias '$ALIAS' is missing"

printf '%s\n' "$KEY_RECORD" | grep -Eq '"algorithm"[[:space:]]*:[[:space:]]*"RSA"' || die "keystore alias is not RSA"
printf '%s\n' "$KEY_RECORD" | grep -Eq '"size"[[:space:]]*:[[:space:]]*2048' || die "keystore alias is not RSA-2048"
printf '%s\n' "$KEY_RECORD" | grep -Eq '"required"[[:space:]]*:[[:space:]]*true' || die "keystore alias does not require Android authentication"
printf '%s\n' "$KEY_RECORD" | grep -Eq '"enforced_by_secure_hardware"[[:space:]]*:[[:space:]]*true' || die "keystore authentication is not hardware-enforced"

# The challenge is random once, then retained owner-only. RSA PKCS#1 v1.5 signing
# of the same challenge gives Naza a repeatable 64-hex Gate-3 passphrase while
# the Android Keystore private key never leaves hardware-backed storage.
if [ -e "$CHALLENGE" ] || [ -L "$CHALLENGE" ]; then
    [ -f "$CHALLENGE" ] && [ ! -L "$CHALLENGE" ] || die "unsafe challenge file"
    [ "$(stat -c %u "$CHALLENGE")" = "$(id -u)" ] || die "challenge has wrong owner"
    [ "$(stat -c %a "$CHALLENGE")" = "600" ] || die "challenge has unsafe permissions"
else
    CHALLENGE_TMP="$(mktemp "$NAZA_DIR/.challenge.XXXXXX")"
    "$PREFIX/bin/python" - "$CHALLENGE_TMP" <<'PY'
from pathlib import Path
import secrets
import sys
Path(sys.argv[1]).write_text(secrets.token_hex(32), encoding="ascii")
PY
    chmod 600 "$CHALLENGE_TMP"
    grep -Eq '^[0-9a-f]{64}$' "$CHALLENGE_TMP" || die "challenge generation failed"
    mv -f -- "$CHALLENGE_TMP" "$CHALLENGE"
    CHALLENGE_TMP=""
fi
grep -Eq '^[0-9a-f]{64}$' "$CHALLENGE" || die "challenge file is malformed"

echo "Authenticate/unlock the Android device, then authorize the Keystore operation."
SIGNATURE_TMP="$(mktemp "$NAZA_DIR/.signature.XXXXXX")"
chmod 600 "$SIGNATURE_TMP"
"$KEYSTORE" sign "$ALIAS" "$SIGN_ALGO" "$CHALLENGE" "$SIGNATURE_TMP" || die "Android Keystore signing failed"
[ -s "$SIGNATURE_TMP" ] || die "Android Keystore returned no signature"

TOKEN_VALUE="$("$PREFIX/bin/python" - "$CHALLENGE" "$SIGNATURE_TMP" <<'PY'
from pathlib import Path
import hashlib
import sys
challenge = Path(sys.argv[1]).read_text(encoding="ascii").strip().encode("ascii")
signature = Path(sys.argv[2]).read_bytes()
print(hashlib.sha256(challenge + signature).hexdigest())
PY
)"
printf '%s\n' "$TOKEN_VALUE" | grep -Eq '^[0-9a-f]{64}$' || die "generated token is malformed"

if [ "$OUTPUT_MODE" = "stdout" ]; then
    printf '%s\n' "$TOKEN_VALUE"
else
    TOKEN_TMP="$(mktemp "$NAZA_DIR/.unlock.token.XXXXXX")"
    chmod 600 "$TOKEN_TMP"
    printf '%s\n' "$TOKEN_VALUE" > "$TOKEN_TMP"
    mv -f -- "$TOKEN_TMP" "$TOKEN"
    TOKEN_TMP=""
    chmod 600 "$TOKEN"
    echo "Gate 3 Android Keystore token ready: $TOKEN"
fi

unset TOKEN_VALUE KEY_DETAIL KEY_RECORD
