#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="${1:-naza-android-recovered-v3}"
DEST="${2:-$ROOT/dist}"
mkdir -p "$DEST"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/$NAME"

(
  cd "$ROOT"
  tar \
    --exclude='.git' \
    --exclude='dist' \
    --exclude='venv-termux' \
    --exclude='models' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='*.log' \
    --exclude='.enc_key' \
    --exclude='chat_history.db*' \
    --exclude='.naza' \
    --exclude='.naza-private-tmp' \
    --exclude='.naza-*lock' \
    --exclude='*.before-*' \
    --exclude='*.pre-*' \
    -cf - .
) | (cd "$TMP/$NAME" && tar -xf -)

# SHA256SUMS describes the actual release payload, not the developer checkout.
(
  cd "$TMP/$NAME"
  find . -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum > SHA256SUMS
)

# Reproducible metadata for the same source tree.
find "$TMP/$NAME" -exec touch -h -t 202609150000 {} +
rm -f "$DEST/$NAME.zip"
(
  cd "$TMP"
  zip -X -q -r "$DEST/$NAME.zip" "$NAME"
)
sha256sum "$DEST/$NAME.zip"
