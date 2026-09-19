#!/data/data/com.termux/files/usr/bin/bash
# Termux-only required biometric + Android keystore unlock token.
set -euo pipefail
umask 077
HOME_T="${HOME:-/data/data/com.termux/files/home}"
NAZA_DIR="$HOME_T/.naza"
ALIAS="${NAZA_KEYSTORE_ALIAS:-naza-unlock}"
CHALLENGE="$NAZA_DIR/challenge"
TOKEN="$NAZA_DIR/unlock.token"
ALGO="${NAZA_SIGN_ALGO:-SHA256withRSA}"
OUTPUT_MODE="${NAZA_TOKEN_OUTPUT:-file}"

[[ "$ALIAS" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || { echo "ERROR: invalid keystore alias" >&2; exit 1; }
[ "$ALGO" = "SHA256withRSA" ] || { echo "ERROR: unsupported signing algorithm" >&2; exit 1; }
[ "$OUTPUT_MODE" = "file" ] || [ "$OUTPUT_MODE" = "stdout" ] || { echo "ERROR: invalid token output mode" >&2; exit 1; }

mkdir -p "$NAZA_DIR"
[ ! -L "$NAZA_DIR" ] || { echo "ERROR: unsafe Naza control directory" >&2; exit 1; }
[ "$(stat -c %u "$NAZA_DIR")" = "$(id -u)" ] || { echo "ERROR: Naza control directory has wrong owner" >&2; exit 1; }
chmod 700 "$NAZA_DIR" 2>/dev/null || true
command -v termux-fingerprint >/dev/null 2>&1 || { echo "ERROR: termux-fingerprint unavailable" >&2; exit 1; }
command -v termux-keystore >/dev/null 2>&1 || { echo "ERROR: termux-keystore unavailable" >&2; exit 1; }
termux-keystore list 2>/dev/null | grep -Fq "$ALIAS" || {
  echo "ERROR: required keystore alias '$ALIAS' is missing. Rerun setup.sh." >&2
  exit 1
}
KEY_DETAIL="$(termux-keystore list -d 2>/dev/null)" || { echo "ERROR: cannot inspect keystore" >&2; exit 1; }
KEY_RECORD="$(printf '%s\n' "$KEY_DETAIL" | awk -v alias="$ALIAS" '
  BEGIN { RS="\\\"alias\\\"[[:space:]]*:[[:space:]]*" }
  index($0, "\"" alias "\"") == 1 { print; found=1; exit }
  END { if (!found) exit 1 }
')" || { echo "ERROR: cannot isolate keystore alias metadata" >&2; exit 1; }
printf '%s\n' "$KEY_RECORD" | grep -Eq '"algorithm"[[:space:]]*:[[:space:]]*"RSA"' || {
  echo "ERROR: keystore alias is not RSA" >&2; exit 1;
}
printf '%s\n' "$KEY_RECORD" | grep -Eq '"required"[[:space:]]*:[[:space:]]*true' || {
  echo "ERROR: keystore alias does not require Android authentication" >&2; exit 1;
}
printf '%s\n' "$KEY_RECORD" | grep -Eq '"enforced_by_secure_hardware"[[:space:]]*:[[:space:]]*true' || {
  echo "ERROR: keystore authentication is not hardware-enforced" >&2; exit 1;
}

AUTH="$(termux-fingerprint -t Naza -s Unlock -d 'Unlock Naza' | tr -d '\r')"
printf '%s\n' "$AUTH" | grep -q 'AUTH_RESULT_SUCCESS' || { echo "Fingerprint failed." >&2; exit 1; }
if [ -e "$CHALLENGE" ] || [ -L "$CHALLENGE" ]; then
  [ -f "$CHALLENGE" ] && [ ! -L "$CHALLENGE" ] || { echo "ERROR: unsafe challenge file" >&2; exit 1; }
  [ "$(stat -c %u "$CHALLENGE")" = "$(id -u)" ] || { echo "ERROR: challenge has wrong owner" >&2; exit 1; }
  [ "$(stat -c %a "$CHALLENGE")" = "600" ] || { echo "ERROR: challenge has unsafe permissions" >&2; exit 1; }
else
  CHALLENGE_TMP="$(mktemp "$NAZA_DIR/.challenge.XXXXXX")"
  trap 'rm -f -- "${CHALLENGE_TMP:-}" "${TOKEN_TMP:-}"' EXIT
  dd if=/dev/urandom bs=32 count=1 status=none | xxd -p -c 64 > "$CHALLENGE_TMP"
  chmod 600 "$CHALLENGE_TMP"
  mv -f -- "$CHALLENGE_TMP" "$CHALLENGE"
fi
grep -Eq '^[0-9a-f]{64}$' "$CHALLENGE" || { echo "ERROR: invalid challenge file" >&2; exit 1; }
SIG="$(termux-keystore sign "$ALIAS" "$ALGO" < "$CHALLENGE" | tr -d '\r\n ')"
[ "${#SIG}" -ge 32 ] || { echo "Keystore signing failed." >&2; exit 1; }
TOKEN_VALUE="$(printf '%s%s' "$(cat "$CHALLENGE")" "$SIG" | sha256sum | awk '{print $1}')"
if [ "$OUTPUT_MODE" = "stdout" ]; then
  printf '%s\n' "$TOKEN_VALUE"
  echo "Naza unlock token streamed." >&2
else
  TOKEN_TMP="$(mktemp "$NAZA_DIR/.unlock.token.XXXXXX")"
  trap 'rm -f -- "${CHALLENGE_TMP:-}" "${TOKEN_TMP:-}"' EXIT
  printf '%s\n' "$TOKEN_VALUE" > "$TOKEN_TMP"
  chmod 600 "$TOKEN_TMP"
  mv -f -- "$TOKEN_TMP" "$TOKEN"
  echo "Naza unlock token ready."
fi
unset TOKEN_VALUE SIG AUTH KEY_DETAIL
