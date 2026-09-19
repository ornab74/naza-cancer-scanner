#!/usr/bin/env bash
set -Eeuo pipefail
ZIP="${1:?usage: $0 path/to/naza-release.zip}"
[ -f "$ZIP" ] || { echo "ERROR: release not found: $ZIP" >&2; exit 1; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
unzip -q "$ZIP" -d "$TMP"
mapfile -t roots < <(find "$TMP" -mindepth 1 -maxdepth 1 -type d -print)
[ "${#roots[@]}" -eq 1 ] || { echo "ERROR: release must contain one top-level directory" >&2; exit 1; }
ROOT="${roots[0]}"
[ -f "$ROOT/SHA256SUMS" ] || { echo "ERROR: SHA256SUMS missing" >&2; exit 1; }
(
  cd "$ROOT"
  sha256sum -c SHA256SUMS
)
[ ! -e "$ROOT/venv-termux" ] || { echo "ERROR: venv leaked into release" >&2; exit 1; }
[ ! -e "$ROOT/models" ] || { echo "ERROR: models leaked into release" >&2; exit 1; }
[ ! -e "$ROOT/.enc_key" ] || { echo "ERROR: secret key leaked into release" >&2; exit 1; }
find "$ROOT" -type f \( -name '*.pyc' -o -name '*.log' -o -name '*.before-*' -o -name '*.pre-*' \) -print -quit | grep -q . && {
  echo "ERROR: generated/recovery debris leaked into release" >&2
  exit 1
}
echo "verify-release: PASS"
