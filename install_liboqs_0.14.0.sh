#!/usr/bin/env bash
# Naza/SpookyNaza pinned Open Quantum Safe backend installer.
# Downloads are cryptographically verified before extraction or installation.
set -euo pipefail
umask 077

LIBOQS_VER="0.14.0"
LIBOQS_URL="https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VER}.tar.gz"
LIBOQS_SHA256="5b0df6138763b3fc4e385d58dbb2ee7c7c508a64a413d76a917529e3a9a207ea"

# Pin the Python wrapper to an exact upstream commit and exact archive digest.
LIBOQS_PY_REF="7906e7879a099fa34217035957d977314f99757d"
LIBOQS_PY_URL="https://github.com/open-quantum-safe/liboqs-python/archive/${LIBOQS_PY_REF}.tar.gz"
LIBOQS_PY_SHA256="ed785fee58e43f20c042db97389ce63091b331278c24f63828c4b8dac0905f8c"

PREFIX="${PREFIX:-$HOME/.local/liboqs-${LIBOQS_VER}}"
SRC_ROOT="${SRC_ROOT:-$HOME/src}"
WORKDIR="${SRC_ROOT}/naza-liboqs-${LIBOQS_VER}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command not found: $1" >&2
    exit 1
  }
}

hash_file() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" | awk '{print $1}'
  else
    echo "ERROR: sha256sum or shasum is required" >&2
    exit 1
  fi
}

verify_sha256() {
  local file="$1" expected="$2" label="$3"
  local got
  got="$(hash_file "$file")"
  if [ "$got" != "$expected" ]; then
    echo "ERROR: ${label} SHA-256 mismatch" >&2
    echo " expected: $expected" >&2
    echo " got:      $got" >&2
    rm -f -- "$file"
    exit 1
  fi
  echo "Verified ${label}: ${got}"
}

need curl
need tar
need cmake
need make
need "$PYTHON_BIN"

mkdir -p "$WORKDIR" "$PREFIX"
cd "$WORKDIR"

OQS_TARBALL="liboqs-${LIBOQS_VER}.tar.gz"
PY_TARBALL="liboqs-python-${LIBOQS_PY_REF}.tar.gz"

printf '\n==> Downloading pinned liboqs %s\n' "$LIBOQS_VER"
curl --fail --show-error --location --proto '=https' --tlsv1.2 \
  "$LIBOQS_URL" -o "$OQS_TARBALL"
verify_sha256 "$OQS_TARBALL" "$LIBOQS_SHA256" "liboqs ${LIBOQS_VER} archive"

# Extraction only happens after the digest has matched.
rm -rf "liboqs-${LIBOQS_VER}"
tar -xzf "$OQS_TARBALL"
cd "liboqs-${LIBOQS_VER}"

printf '\n==> Building liboqs with SpookyNaza mechanisms\n'
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON \
  '-DOQS_MINIMAL_BUILD=KEM_ml_kem_1024;KEM_hqc_256' \
  -DOQS_DIST_BUILD=ON \
  -DOQS_ENABLE_KEM_ML_KEM=ON \
  -DOQS_ENABLE_KEM_HQC=ON \
  -DOQS_ENABLE_SIG_ML_DSA=OFF
cmake --build build -j"$(nproc 2>/dev/null || echo 2)"
cmake --install build

cd "$WORKDIR"
printf '\n==> Downloading pinned liboqs-python wrapper\n'
curl --fail --show-error --location --proto '=https' --tlsv1.2 \
  "$LIBOQS_PY_URL" -o "$PY_TARBALL"
verify_sha256 "$PY_TARBALL" "$LIBOQS_PY_SHA256" "liboqs-python ${LIBOQS_PY_REF} archive"

export OQS_INSTALL_PATH="$PREFIX"
unset LD_PRELOAD PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP
export LD_LIBRARY_PATH="${PREFIX}/lib"

# Deliberately no --user: when Naza's venv is active, install into that venv.
"$PYTHON_BIN" -m pip install --no-deps --force-reinstall "$PY_TARBALL"

printf '\n==> Verifying SpookyNaza OQS backend\n'
"$PYTHON_BIN" - <<'PY'
import oqs
mechs = set(oqs.get_enabled_kem_mechanisms())
required = {"ML-KEM-1024", "HQC-256"}
missing = sorted(required - mechs)
if mechs != required or oqs.get_enabled_sig_mechanisms():
    raise SystemExit("ERROR: liboqs algorithm set differs from the minimal runtime policy")
if missing:
    raise SystemExit("ERROR: required liboqs mechanisms missing: " + ", ".join(missing))
print("SpookyNaza OQS backend ready: ML-KEM-1024 + HQC-256")
PY

cat > "${PREFIX}/naza-oqs.env" <<ENV
export OQS_INSTALL_PATH='${PREFIX}'
export LD_LIBRARY_PATH='${PREFIX}/lib'
ENV
chmod 600 "${PREFIX}/naza-oqs.env"

echo
echo "Installed and verified liboqs ${LIBOQS_VER}: ${PREFIX}"
echo "Pinned native archive SHA-256: ${LIBOQS_SHA256}"
echo "Pinned Python wrapper ref: ${LIBOQS_PY_REF}"
echo "Pinned wrapper SHA-256: ${LIBOQS_PY_SHA256}"
