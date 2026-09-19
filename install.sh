#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
HOME="${HOME:-/data/data/com.termux/files/home}"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAZA_DIR="${NAZA_DIR:-$HOME/naza}"

fail() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

[ -d "$PREFIX" ] || fail "This installer must run inside native Termux. PREFIX=$PREFIX"
command -v pkg >/dev/null 2>&1 || fail "Termux pkg command not found."
command -v cp >/dev/null 2>&1 || fail "cp command not found."
command -v mv >/dev/null 2>&1 || fail "mv command not found."
command -v rm >/dev/null 2>&1 || fail "rm command not found."

printf '\n== NAZA recovered native-Android installer ==\n'
printf 'Source: %s\nTarget: %s\n' "$SOURCE_DIR" "$NAZA_DIR"

mkdir -p "$NAZA_DIR"
[ ! -L "$NAZA_DIR" ] || fail "Refusing symbolic-link target: $NAZA_DIR"
chmod 700 "$NAZA_DIR"

source_real="$(readlink -f "$SOURCE_DIR")"
target_real="$(readlink -f "$NAZA_DIR")"

# If invoked from the already-installed tree, there is nothing to redeploy.
if [ "$source_real" != "$target_real" ]; then
  case "$source_real/" in
    "$target_real/"*) fail "Source directory may not be nested inside target: $SOURCE_DIR" ;;
  esac

  STAGE_DIR="$(mktemp -d "$HOME/.naza-install-stage.XXXXXX")"
  KEEP_DIR="$(mktemp -d "$HOME/.naza-install-keep.XXXXXX")"
  cleanup() {
    rm -rf -- "$STAGE_DIR" "$KEEP_DIR"
  }
  trap cleanup EXIT INT TERM HUP

  # Stage the replacement first. Runtime/generated paths are never imported
  # from the source checkout into the canonical installation.
  shopt -s nullglob
  for src in "$SOURCE_DIR"/* "$SOURCE_DIR"/.[!.]* "$SOURCE_DIR"/..?*; do
    [ -e "$src" ] || continue
    base="$(basename "$src")"
    case "$base" in
      .git|dist|venv-termux|models|.enc_key|.naza|.naza-private-tmp|chat_history.db*|.naza-native-repair.log|.naza-native-repair.lock|.naza-rotation*)
        continue
        ;;
    esac
    cp -a -- "$src" "$STAGE_DIR/"
  done

  [ -f "$STAGE_DIR/main.py" ] || fail "Staged tree is missing main.py"
  [ -f "$STAGE_DIR/install-native-termux-repair.sh" ] || fail "Staged tree is missing native repair installer"
  [ -f "$STAGE_DIR/run_naza.sh" ] || fail "Staged tree is missing run_naza.sh"

  # Preserve local runtime state and the repository metadata, if present.
  preserve_one() {
    local path="$1"
    [ -e "$path" ] || [ -L "$path" ] || return 0
    mv -- "$path" "$KEEP_DIR/"
  }

  preserve_one "$NAZA_DIR/.git"
  preserve_one "$NAZA_DIR/venv-termux"
  preserve_one "$NAZA_DIR/models"
  preserve_one "$NAZA_DIR/.enc_key"
  preserve_one "$NAZA_DIR/.naza"
  preserve_one "$NAZA_DIR/.naza-private-tmp"
  preserve_one "$NAZA_DIR/.naza-native-repair.log"
  preserve_one "$NAZA_DIR/.naza-native-repair.lock"

  for path in "$NAZA_DIR"/chat_history.db* "$NAZA_DIR"/.naza-rotation*; do
    [ -e "$path" ] || [ -L "$path" ] || continue
    preserve_one "$path"
  done

  # Replace the old application tree using only the standard shell utilities
  # already present in Termux; no extra synchronization package is required.
  for path in "$NAZA_DIR"/* "$NAZA_DIR"/.[!.]* "$NAZA_DIR"/..?*; do
    [ -e "$path" ] || [ -L "$path" ] || continue
    rm -rf -- "$path"
  done

  cp -a -- "$STAGE_DIR"/. "$NAZA_DIR"/

  for path in "$KEEP_DIR"/* "$KEEP_DIR"/.[!.]* "$KEEP_DIR"/..?*; do
    [ -e "$path" ] || [ -L "$path" ] || continue
    mv -- "$path" "$NAZA_DIR/"
  done

  trap - EXIT INT TERM HUP
  cleanup
fi

chmod 700 \
  "$NAZA_DIR/install.sh" \
  "$NAZA_DIR/install-native-termux-repair.sh" \
  "$NAZA_DIR/install_liboqs_0.14.0.sh" \
  "$NAZA_DIR/run_naza.sh" \
  "$NAZA_DIR/naza_unlock.sh" \
  "$NAZA_DIR/naza-termux-boot.sh" 2>/dev/null || true

cd "$NAZA_DIR"
exec bash "$NAZA_DIR/install-native-termux-repair.sh"
