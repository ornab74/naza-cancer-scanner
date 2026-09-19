import os, sys, time, json, shutil, hashlib, asyncio, threading, httpx, aiosqlite, getpass, math, random, re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List, Tuple, Callable, Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import hmac
import secrets
import stat as statmod
import ctypes
from argon2.low_level import ARGON2_VERSION, Type as Argon2Type, hash_secret_raw
from llama_cpp import Llama
import spooky_trihybrid as tri
import naza_storage as storage
from spooky_combiner import (
    create_envelope as spooky_create_envelope,
    open_envelope as spooky_open_envelope,
    self_test as spooky_self_test,
    status as spooky_status,
    SUITE as SPOOKY_SUITE,
    KEMS as SPOOKY_KEMS,
    SpookyCombinerError,
)

try:
    os.umask(0o077)
except Exception:
    pass

_PROCESS_NONDUMPABLE = False
PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39
_PROCESS_NO_NEW_PRIVS = False
try:
    _libc = ctypes.CDLL(None, use_errno=True)
    _PROCESS_NONDUMPABLE = (
        _libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
        and _libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
    )
    _PROCESS_NO_NEW_PRIVS = (
        _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
        and _libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1
    )
except Exception:
    pass
if os.environ.get("NAZA_REQUIRE_PROCESS_HARDENING") == "1":
    if not _PROCESS_NONDUMPABLE:
        raise RuntimeError("Could not enforce non-dumpable process policy")
    if not _PROCESS_NO_NEW_PRIVS:
        raise RuntimeError("Could not enforce no-new-privileges process policy")

MODEL_REPO = "https://huggingface.co/tensorblock/llama3-small-GGUF/resolve/main/"
MODEL_FILE = "llama3-small-Q3_K_M.gguf"
MAX_MODEL_DOWNLOAD = 8 * 1024 * 1024 * 1024
MODELS_DIR = Path("models")
MODEL_PATH = MODELS_DIR / MODEL_FILE
ENCRYPTED_MODEL = MODEL_PATH.with_suffix(MODEL_PATH.suffix + ".aes")
PRIVATE_TMP_DIR = Path(".naza-private-tmp")
SESSION_MODEL_PATH = PRIVATE_TMP_DIR / MODEL_FILE
DB_PATH = Path("chat_history.db.aes")
KEY_PATH = Path(".enc_key")
EXPECTED_HASH = "8e4f4856fb84bafb895f1eb08e6c03e4be613ead2d942f91561aeac742a619aa"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
PRIVATE_TMP_DIR.mkdir(mode=0o700, exist_ok=True)

CSI = "\x1b["
def clear_screen(): sys.stdout.write(CSI + "2J" + CSI + "H")
def show_cursor(): sys.stdout.write(CSI + "?25h")
def color(text, fg=None, bold=False):
    codes=[]
    if fg: codes.append(str(fg))
    if bold: codes.append('1')
    if not codes: return text
    return f"\x1b[{';'.join(codes)}m{text}\x1b[0m"
def boxed(title: str, lines: List[str], width: int = 72):
    top = "+" + "-"*(width-2) + "+"
    bot = "+" + "-"*(width-2) + "+"
    title_line = f"| {color(title, fg=36, bold=True):{width-4}} |"
    body=[]
    for l in lines:
        if len(l) > width-4:
            chunks = [l[i:i+width-4] for i in range(0,len(l),width-4)]
        else:
            chunks=[l]
        for c in chunks:
            body.append(f"| {c:{width-4}} |")
    return "\n".join([top, title_line] + body + [bot])

def drain_stdin():

    try:
        import termios, tty, fcntl
        fd = sys.stdin.fileno()
        try:
            old = termios.tcgetattr(fd)
            new = list(old)
            new[3] = new[3] & ~(termios.ICANON | termios.ECHO)
            termios.tcsetattr(fd, termios.TCSANOW, new)
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            try:
                while True:
                    chunk = os.read(fd, 256)
                    if not chunk:
                        break
            except BlockingIOError:
                pass
            except Exception:
                pass
            fcntl.fcntl(fd, fcntl.F_SETFL, fl)
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except Exception:
            pass
    except Exception:
        pass
    try:
        show_cursor()
    except Exception:
        pass


def read_menu_choice(num_items:int, prompt="Enter number: ")->int:
    drain_stdin()
    while True:
        try:
            s = input(prompt).strip()
        except EOFError:
            raise SystemExit("Input stream closed")
        if not s:
            print("Pick a number 1-{}.".format(num_items))
            continue
        if s.isdigit():
            n = int(s)
            if 1 <= n <= num_items:
                return n - 1
        print("Pick a number 1-{}.".format(num_items))

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aes.encrypt(nonce, data, None)

def aes_decrypt(data: bytes, key: bytes) -> bytes:
    aes = AESGCM(key)
    nonce, ct = data[:12], data[12:]
    return aes.decrypt(nonce, ct, None)

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not statmod.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("refusing to hash a non-regular file")
        with os.fdopen(fd, "rb", closefd=False) as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    finally:
        os.close(fd)
    return h.hexdigest()

KEY_MAGIC = b"NKEY2"
KEY_MAGIC3 = b"NKEY3"
KEY_KDF_ROUNDS = 400_000
NKEY4_VERSION = 2
NKEY4_ARGON2_TIME = 3
NKEY4_ARGON2_MEMORY_KIB = 64 * 1024
NKEY4_ARGON2_PARALLELISM = 1
MIN_NEW_PASSPHRASE_LENGTH = 12
KEY_FLAG_PASSPHRASE = 0x01
LOCK_PATH = Path("naza.lock.json")
MAC_SUFFIX = ".mac"
LIBOQS_VER = "0.14.0"
LIBOQS_URL = "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/0.14.0.tar.gz"
LIBOQS_SHA256 = "5b0df6138763b3fc4e385d58dbb2ee7c7c508a64a413d76a917529e3a9a207ea"
LIBOQS_PY_VER = "0.12.0"
OQS_INSTALL_SCRIPT_PATH = Path("install_liboqs_0.14.0.sh")
SPOOKY_LAB_PATH = Path(".spooky_combiner_1.lab")
SPOOKY_LAB_MAGIC = b"NSC1"
DEFAULT_CRYPTO_MODE = os.environ.get("NAZA_CRYPTO_MODE", "tri").strip().lower()
if DEFAULT_CRYPTO_MODE not in ("tri", "classical"):
    DEFAULT_CRYPTO_MODE = "tri"

OQS_INSTALL_SCRIPT = r'''#!/usr/bin/env bash

set -euo pipefail

LIBOQS_VER="0.14.0"
LIBOQS_URL="https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VER}.tar.gz"
LIBOQS_SHA256="5b0df6138763b3fc4e385d58dbb2ee7c7c508a64a413d76a917529e3a9a207ea"


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

printf '
==> Downloading pinned liboqs %s
' "$LIBOQS_VER"
curl --fail --show-error --location --proto '=https' --tlsv1.2 \
  "$LIBOQS_URL" -o "$OQS_TARBALL"
verify_sha256 "$OQS_TARBALL" "$LIBOQS_SHA256" "liboqs ${LIBOQS_VER} archive"

rm -rf "liboqs-${LIBOQS_VER}"
tar -xzf "$OQS_TARBALL"
cd "liboqs-${LIBOQS_VER}"

printf '
==> Building liboqs with SpookyNaza mechanisms
'
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_DIST_BUILD=ON \
  -DOQS_ENABLE_KEM_ML_KEM=ON \
  -DOQS_ENABLE_KEM_HQC=ON \
  -DOQS_ENABLE_SIG_ML_DSA=ON
cmake --build build -j"$(nproc 2>/dev/null || echo 2)"
cmake --install build

cd "$WORKDIR"
printf '
==> Downloading pinned liboqs-python wrapper
'
curl --fail --show-error --location --proto '=https' --tlsv1.2 \
  "$LIBOQS_PY_URL" -o "$PY_TARBALL"
verify_sha256 "$PY_TARBALL" "$LIBOQS_PY_SHA256" "liboqs-python ${LIBOQS_PY_REF} archive"

export OQS_INSTALL_PATH="$PREFIX"
export LD_LIBRARY_PATH="${PREFIX}/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"


"$PYTHON_BIN" -m pip install --no-deps --force-reinstall "$PY_TARBALL"

printf '
==> Verifying SpookyNaza OQS backend
'
"$PYTHON_BIN" - <<'PY'
import oqs
mechs = set(oqs.get_enabled_kem_mechanisms())
required = {"ML-KEM-1024", "HQC-256"}
missing = sorted(required - mechs)
if missing:
    raise SystemExit("ERROR: required liboqs mechanisms missing: " + ", ".join(missing))
print("SpookyNaza OQS backend ready: ML-KEM-1024 + HQC-256")
PY

cat > "${PREFIX}/naza-oqs.env" <<ENV
export OQS_INSTALL_PATH='${PREFIX}'
export LD_LIBRARY_PATH='${PREFIX}/lib':\${LD_LIBRARY_PATH:-}
ENV
chmod 600 "${PREFIX}/naza-oqs.env"

echo
echo "Installed and verified liboqs ${LIBOQS_VER}: ${PREFIX}"
echo "Pinned native archive SHA-256: ${LIBOQS_SHA256}"
echo "Pinned Python wrapper ref: ${LIBOQS_PY_REF}"
echo "Pinned wrapper SHA-256: ${LIBOQS_PY_SHA256}"
'''


def write_oqs_install_script(dest: Optional[Path] = None) -> Path:
    dest = dest or OQS_INSTALL_SCRIPT_PATH
    data = OQS_INSTALL_SCRIPT.encode("utf-8")
    _atomic_write_private(dest, data)
    try:
        os.chmod(dest, 0o700)
    except Exception:
        pass
    return dest


def oqs_status_line() -> str:
    if _OQS is None:
        return "liboqs: not loaded (run pinned installer 0.14.0)"
    try:
        enabled = set(_OQS.get_enabled_kem_mechanisms())
    except Exception:
        return "liboqs: unavailable"
    ml = "MLK" if "ML-KEM-1024" in enabled else "no-MLK"
    hqc = "HQC" if "HQC-256" in enabled else "no-HQC"
    return f"liboqs: {ml}+{hqc}"

def spooky_status_line() -> str:
    st = spooky_status(_OQS)
    if st.ready:
        return "SC1: research-ready"
    if _OQS is None:
        return "SC1: liboqs missing"
    return "SC1: missing " + "/".join(st.missing)


def _hkdf_sha512(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA512(), length=length, salt=salt, info=info).derive(ikm)


def _chmod_private(path: Path):
    _assert_private_regular(path, "private file")


def _is_symlink(path: Path) -> bool:
    try:
        return os.path.islink(str(path))
    except Exception:
        return False


def secure_unlink(path: Path, passes: int = 2):
    try:
        if not path.exists() or _is_symlink(path):
            if path.exists():
                path.unlink()
            return
        size = path.stat().st_size
        with path.open("r+b") as f:
            for _ in range(max(1, passes)):
                f.seek(0)
                left = size
                while left > 0:
                    n = min(65536, left)
                    f.write(os.urandom(n))
                    left -= n
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
    except Exception:
        try:
            path.unlink()
        except Exception:
            pass


def _assert_private_regular(path: Path, label: str):
    if _is_symlink(path):
        raise RuntimeError("{} is a symlink; refusing to use it".format(label))
    try:
        st = os.stat(str(path), follow_symlinks=False)
    except TypeError:
        st = os.lstat(str(path))
    except FileNotFoundError:
        return
    mode = st.st_mode
    if not statmod.S_ISREG(mode):
        raise RuntimeError("{} is not a regular file".format(label))
    if st.st_uid != os.geteuid():
        raise RuntimeError("{} is owned by another user".format(label))
    if mode & 0o077:
        os.chmod(str(path), 0o600)
        st = os.lstat(str(path))
        if st.st_mode & 0o077:
            raise RuntimeError("{} is readable by group/other".format(label))


def _read_first(path: str, n: int = 256) -> str:
    try:
        with open(path, "r") as f:
            return f.read(n).strip()
    except Exception:
        return ""


def hardware_fingerprint() -> bytes:
    parts = []
    for p in (
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
        "/sys/class/dmi/id/product_uuid",
        "/sys/class/dmi/id/board_serial",
        "/sys/class/dmi/id/product_serial",
    ):
        v = _read_first(p, 128)
        if v:
            parts.append(v)
    cpu = _read_text("/proc/cpuinfo") or ""
    model = ""
    for line in cpu.splitlines():
        if line.lower().startswith("model name") or line.lower().startswith("hardware"):
            model = line.split(":", 1)[-1].strip()
            break
    if model:
        parts.append(model)
    try:
        u = os.uname()
        parts.append(u.nodename)
        parts.append(u.release)
        parts.append(u.machine)
    except Exception:
        pass
    v = _read_first("/proc/sys/kernel/osrelease", 80)
    if v:
        parts.append(v)
    blob = "|".join(parts).encode("utf-8", "ignore") or b"unknown-host"
    return hashlib.sha256(blob).digest()


_OQS = None
try:
    import oqs as _OQS
except Exception:
    _OQS = None


def _pq_available() -> bool:
    if _OQS is None:
        return False
    try:
        return "ML-KEM-1024" in _OQS.get_enabled_kem_mechanisms()
    except Exception:
        return False


def _pq_encapsulate(data_key: bytes) -> Tuple[bytes, bytes]:

    if not _pq_available():
        return b"", b""
    try:
        with _OQS.KeyEncapsulation("ML-KEM-1024") as kem:
            pub = kem.generate_keypair()
            ct, ss = kem.encap_secret(pub)
            wrap = AESGCM(_hkdf_sha512(ss, b"pq-salt", b"naza-mlkem-wrap", 32)).encrypt(os.urandom(12), data_key, pub)
            return pub, wrap
    except Exception:
        return b"", b""


_PW_FAILS = 0
_PW_LOCK_UNTIL = 0.0


def _pw_guard():
    global _PW_FAILS, _PW_LOCK_UNTIL
    now = time.time()
    if now < _PW_LOCK_UNTIL:
        wait = int(_PW_LOCK_UNTIL - now) + 1
        raise RuntimeError("passphrase cooldown {}s".format(wait))


def _pw_fail():
    global _PW_FAILS, _PW_LOCK_UNTIL
    _PW_FAILS += 1
    _PW_LOCK_UNTIL = time.time() + min(120.0, 2.0 ** min(6, _PW_FAILS))


def _pw_ok():
    global _PW_FAILS, _PW_LOCK_UNTIL
    _PW_FAILS = 0
    _PW_LOCK_UNTIL = 0.0


def derive_kek(salt: bytes, passphrase: Optional[str] = None) -> bytes:
    material = hardware_fingerprint()
    if passphrase:
        material += b"\x1e" + passphrase.encode("utf-8")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KEY_KDF_ROUNDS)
    return kdf.derive(material)


def _atomic_write_private(path: Path, data: bytes):
    storage.atomic_write(path, data)


RAINBOW_BIND = hashlib.sha256(
    b"naza-rainbow-12|violet|indigo|blue|cyan|green|chartreuse|yellow|amber|orange|red|crimson|magenta"
).digest()


def _wrap_aad() -> bytes:
    return hardware_fingerprint() + b"|" + RAINBOW_BIND


def _hybrid_kek(salt: bytes, passphrase: Optional[str] = None, lane: bytes = b"A") -> bytes:

    seed = derive_kek(salt, passphrase)
    hw = hardware_fingerprint()
    return _hkdf_sha512(seed + hw + RAINBOW_BIND, salt, b"naza-hybrid-aes-v1|" + lane + b"|" + hw[:32], 32)


def _argon2_lane(secret: bytes, salt: bytes, label: bytes) -> bytes:
    lane_salt = hashlib.sha256(b"NAZA-NKEY4-V2-SALT\x00" + label + salt).digest()[:16]
    return hash_secret_raw(
        secret=secret,
        salt=lane_salt,
        time_cost=NKEY4_ARGON2_TIME,
        memory_cost=NKEY4_ARGON2_MEMORY_KIB,
        parallelism=NKEY4_ARGON2_PARALLELISM,
        hash_len=32,
        type=Argon2Type.ID,
        version=ARGON2_VERSION,
    )


def _nkey4_protector(salt: bytes, passphrase: Optional[str], version: int) -> bytes:

    if not isinstance(salt, bytes) or len(salt) != 16:
        raise ValueError("NKEY4 salt must be 16 bytes")
    if version == 1:
        return _hybrid_kek(salt, passphrase or None, b"TRI")
    if version != NKEY4_VERSION:
        raise ValueError("unsupported NKEY4 version")
    device_secret = hardware_fingerprint()
    if passphrase is not None and (not isinstance(passphrase, str) or not passphrase):
        raise ValueError("NKEY4 gate secret must be non-empty")
    gate_secret = passphrase.encode("utf-8") if passphrase else (
        b"machine-only\x00" + device_secret
    )
    gate_lane = _argon2_lane(gate_secret, salt, b"gate")
    device_lane = _argon2_lane(device_secret, salt, b"device")
    return _hkdf_sha512(
        gate_lane + device_lane,
        salt,
        b"naza/nkey4/v2/argon2id-dual-lane/tri-protector|" + RAINBOW_BIND,
        32,
    )


def build_trihybrid_key(data_key: bytes, passphrase: Optional[str] = None) -> bytes:
    if not isinstance(data_key, bytes) or len(data_key) != 32:
        raise ValueError("Data key must be exactly 32 bytes")
    salt = os.urandom(16)
    flags = KEY_FLAG_PASSPHRASE if passphrase else 0
    header = b"NKEY4" + bytes([NKEY4_VERSION, flags]) + salt
    protector = _nkey4_protector(salt, passphrase, NKEY4_VERSION)
    envelope = tri.create_envelope(data_key, protector, _OQS, header)
    if not hmac.compare_digest(tri.open_envelope(envelope, protector, _OQS, header), data_key):
        raise ValueError("tri-hybrid verification failed")
    return header + envelope


def save_wrapped_key(data_key: bytes, passphrase: Optional[str] = None, mode: Optional[str] = None):
    if mode is None:
        mode = "tri"
    if mode not in ("classical", "tri"):
        raise ValueError("unknown encryption mode")
    if mode == "tri":
        _atomic_write_private(KEY_PATH, build_trihybrid_key(data_key, passphrase))
        return

    salt = os.urandom(16)
    kek_a = _hybrid_kek(salt, passphrase, b"A")
    kek_b = _hybrid_kek(salt, passphrase, b"B")
    nonce = os.urandom(12)
    hw = hardware_fingerprint()
    ed = Ed25519PrivateKey.generate()
    x = X25519PrivateKey.generate()
    payload = data_key + ed.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ) + x.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    aad = _wrap_aad()
    inner = AESGCM(kek_a).encrypt(nonce, payload, aad)
    ct = AESGCM(kek_b).encrypt(nonce, inner, aad + b"|lane-b")
    flags = KEY_FLAG_PASSPHRASE if passphrase else 0
    ed_pub = ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    x_pub = x.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    body = bytes([1, flags]) + salt + nonce + ed_pub + x_pub + ct
    sig = ed.sign(KEY_MAGIC3 + body)
    blob = KEY_MAGIC3 + body + sig
    try:
        if _pq_available():
            with _OQS.KeyEncapsulation("ML-KEM-1024") as kem:
                pub = kem.generate_keypair()
                sk = kem.export_secret_key()
                pqct, ss = kem.encap_secret(pub)
                nonce_p = os.urandom(12)
                wrapped = nonce_p + AESGCM(_hkdf_sha512(ss, b"pq-salt", b"naza-mlkem-wrap", 32)).encrypt(nonce_p, data_key, pub)
                sk_blob = AESGCM(kek_a).encrypt(os.urandom(12), sk, pub)
            blob += (
                b"PQ1"
                + len(pub).to_bytes(2, "big")
                + len(sk_blob).to_bytes(2, "big")
                + len(wrapped).to_bytes(2, "big")
                + pub
                + sk_blob
                + wrapped
            )
    except Exception:
        pass
    _atomic_write_private(KEY_PATH, blob)
    _write_lock_manifest(data_key, ed_pub)


def _unwrap_nkey3(blob: bytes, passphrase: Optional[str] = None) -> bytes:

    if not blob.startswith(KEY_MAGIC3) or len(blob) < 5 + 2 + 16 + 12 + 32 + 32 + 16 + 64:
        raise ValueError("short nkey3")
    core = blob[:291]
    sig = core[-64:]
    signed = core[:-64]
    body = signed[5:]
    flags = body[1]
    salt = body[2:18]
    nonce = body[18:30]
    ed_pub = body[30:62]
    ct = body[94:]
    Ed25519PublicKey.from_public_bytes(ed_pub).verify(sig, signed)
    need_pw = bool(flags & KEY_FLAG_PASSPHRASE)
    if need_pw and not passphrase:
        passphrase = getpass.getpass("Key passphrase: ")
    try:
        _pw_guard()
        kek_a = _hybrid_kek(salt, passphrase if need_pw else None, b"A")
        kek_b = _hybrid_kek(salt, passphrase if need_pw else None, b"B")
        aad = _wrap_aad()
        inner = AESGCM(kek_b).decrypt(nonce, ct, aad + b"|lane-b")
        payload = AESGCM(kek_a).decrypt(nonce, inner, aad)
        _pw_ok()
    except Exception:
        if need_pw:
            _pw_fail()
        raise
    if len(payload) < 32:
        raise ValueError("short payload")
    return payload[:32]


def _unwrap_nkey2(blob: bytes, passphrase: Optional[str] = None) -> bytes:
    flags = blob[6]
    salt = blob[7:23]
    nonce = blob[23:35]
    ct = blob[35:]
    need_pw = bool(flags & KEY_FLAG_PASSPHRASE)
    if need_pw and not passphrase:
        passphrase = getpass.getpass("Key passphrase: ")
    kek = derive_kek(salt, passphrase if need_pw else None)
    return AESGCM(kek).decrypt(nonce, ct, hardware_fingerprint())


def _mac_key(data_key: bytes) -> bytes:
    return _hkdf_sha512(data_key, b"naza-mac-salt", b"naza-file-mac-v1", 32)


def write_file_mac(path: Path, data_key: bytes):
    if not path.exists():
        return
    raw = storage.read_private(path)
    tag = hmac.new(_mac_key(data_key), raw, hashlib.sha256).digest()
    macp = Path(str(path) + MAC_SUFFIX)
    _atomic_write_private(macp, tag)


def verify_file_mac(path: Path, data_key: bytes) -> bool:
    macp = Path(str(path) + MAC_SUFFIX)
    if not path.exists():
        return False
    if not macp.exists():
        return False  # caller may treat as "no mac yet"
    raw = storage.read_private(path)
    tag = storage.read_private(macp, 64)
    expect = hmac.new(_mac_key(data_key), raw, hashlib.sha256).digest()
    return hmac.compare_digest(tag, expect)


def _write_lock_manifest(data_key: bytes, ed_pub: bytes):
    rec = {
        "profile": "naza-hybrid-nkey3",
        "kdf": "PBKDF2-SHA256 + HKDF-SHA512",
        "wrap": "AES-256-GCM",
        "sign": "Ed25519",
        "dh": "X25519",
        "pq_note": "Production NKEY3 remains classical-hybrid. SpookyCombiner-1 is an isolated research lab using ML-KEM-1024 + HQC-256 and never wraps the live Naza data key.",
        "ed25519_pub_hex": ed_pub.hex(),
        "hardware_fp_sha256": hashlib.sha256(hardware_fingerprint()).hexdigest(),
        "model_pin_sha256": EXPECTED_HASH,
        "written": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    _atomic_write_private(LOCK_PATH, json.dumps(rec, indent=2).encode("utf-8"))


def load_data_key(passphrase: Optional[str] = None) -> bytes:
    if not KEY_PATH.exists():
        raise FileNotFoundError("no key file")
    _assert_private_regular(KEY_PATH, "key file")
    blob = storage.read_private(KEY_PATH, 1024 * 1024)
    if blob.startswith(b"NKEY4"):
        try:
            if len(blob) > tri.MAX_ENVELOPE + 23 or blob[5] not in (1, NKEY4_VERSION) or blob[6] not in (0, KEY_FLAG_PASSPHRASE):
                raise ValueError("invalid NKEY4 header")
            need_pw = bool(blob[6] & KEY_FLAG_PASSPHRASE)
            if need_pw and not passphrase:
                passphrase = getpass.getpass("Key passphrase: ")
            _pw_guard()
            protector = _nkey4_protector(blob[7:23], passphrase if need_pw else None, blob[5])
            key = tri.open_envelope(blob[23:], protector, _OQS, blob[:23])
            if len(key) != 32:
                raise ValueError("invalid data key")
            if blob[5] == 1:
                _atomic_write_private(KEY_PATH, build_trihybrid_key(
                    key, passphrase if need_pw else None
                ))
            _pw_ok()
            return key
        except Exception:
            _pw_fail()
            raise SpookyCombinerError(tri.ERROR) from None
    if blob.startswith(KEY_MAGIC3) and len(blob) > 99:
        return _unwrap_nkey3(blob, passphrase)
    if blob.startswith(KEY_MAGIC) and len(blob) > 35:
        return _unwrap_nkey2(blob, passphrase)
    if len(blob) not in (32, 48) or blob.startswith((b"NKEY", b"SPK")):
        raise ValueError("unknown or damaged key format")
    if len(blob) >= 48:
        key = blob[16:48]
    else:
        key = blob[:32]
    try:
        save_wrapped_key(key, None)
        print("Key file upgraded to SpookyNaza NKEY4 tri-hybrid wrap.")
    except Exception:
        pass
    return key


UNLOCK_CANDIDATES = [
    Path(os.environ["NAZA_UNLOCK_FILE"]) if os.environ.get("NAZA_UNLOCK_FILE") else None,
    Path("/data/data/com.termux/files/home/.naza/unlock.token"),
    Path.home() / ".naza" / "unlock.token",
    Path("/root/.naza/unlock.token"),
]
UNLOCK_MAX_AGE = 30.0
_UNLOCK_FD_READ = False
_UNLOCK_FD_TOKEN: Optional[str] = None
_UNLOCK_FD_REQUIRED = "NAZA_UNLOCK_FD" in os.environ


def _read_unlock_fd() -> Optional[str]:

    global _UNLOCK_FD_READ, _UNLOCK_FD_TOKEN
    if _UNLOCK_FD_READ:
        return _UNLOCK_FD_TOKEN
    _UNLOCK_FD_READ = True
    raw_fd = os.environ.pop("NAZA_UNLOCK_FD", "")
    if not raw_fd:
        return None
    try:
        fd = int(raw_fd, 10)
        if fd < 3 or fd > 9:
            return None
        chunks = []
        remaining = 129
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks).decode("ascii").strip()
        if re.fullmatch(r"[0-9a-f]{64}", raw):
            _UNLOCK_FD_TOKEN = raw
    except Exception:
        _UNLOCK_FD_TOKEN = None
    finally:
        try:
            os.close(int(raw_fd, 10))
        except Exception:
            pass
    return _UNLOCK_FD_TOKEN


def read_unlock_token() -> Optional[str]:
    """Token written by Termux naza_unlock.sh after fingerprint + keystore sign."""
    if "NAZA_UNLOCK_FD" in os.environ or _UNLOCK_FD_READ:
        return _read_unlock_fd()
    now = time.time()
    for p in UNLOCK_CANDIDATES:
        if p is None:
            continue
        try:
            st = os.lstat(str(p))
            if not statmod.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
                continue
            if st.st_mode & 0o077:
                continue
            age = now - st.st_mtime
            if age < 0 or age > UNLOCK_MAX_AGE:
                continue
            raw = storage.read_private(p, 128).decode("ascii").strip()
            if re.fullmatch(r"[0-9a-f]{64}", raw):
                return raw
        except Exception:
            continue
    return None


def consume_unlock_token():
    global _UNLOCK_FD_TOKEN
    _UNLOCK_FD_TOKEN = None
    for p in UNLOCK_CANDIDATES:
        if p is None:
            continue
        try:
            if os.path.lexists(str(p)):
                p.unlink()
        except Exception:
            pass


def get_or_create_key() -> bytes:
    if KEY_PATH.exists():
        return load_data_key()
    key = AESGCM.generate_key(256)
    save_wrapped_key(key, None)
    print("New data key wrapped to this machine and stored privately.")
    return key


def derive_key_from_passphrase(pw:str, salt:Optional[bytes]=None) -> Tuple[bytes, bytes]:
    if salt is None: salt = os.urandom(16)
    kdf_der = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KEY_KDF_ROUNDS)
    derived = kdf_der.derive(pw.encode("utf-8"))
    return salt, derived


def validate_new_passphrase(passphrase: str) -> None:
    if len(passphrase) < MIN_NEW_PASSPHRASE_LENGTH:
        raise ValueError("New passphrase must be at least {} characters".format(MIN_NEW_PASSPHRASE_LENGTH))


def ensure_key_interactive() -> bytes:
    token = read_unlock_token()
    if _UNLOCK_FD_REQUIRED and not token:
        raise RuntimeError("Required streamed biometric authorization is missing or malformed")
    if KEY_PATH.exists():
        try:
            return load_data_key(token)
        except Exception as e:
            print(f"Could not unwrap key ({e}).")
            token = read_unlock_token()
            if token:
                print("Using Termux fingerprint token.")
                return load_data_key(token)
            print("No fresh unlock token. In Termux (not proot) run: bash naza_unlock.sh")
            raise
    print("No wrapped key on disk.")
    print("  1) Machine-bound hardware key (no interactive gate)")
    print("  2) Typed passphrase gate")
    print("  3) Termux fingerprint + keystore token gate (no typing in proot)")
    opt = input("Choose (1/2/3): ").strip()
    key = AESGCM.generate_key(256)
    if opt == "1":
        save_wrapped_key(key, None)
        print("Saved Argon2id hardware-bound key without an interactive gate.")
    elif opt == "2":
        pw = getpass.getpass("Enter passphrase: ")
        pw2 = getpass.getpass("Confirm: ")
        if not pw or pw != pw2:
            print("Passphrase is empty or does not match.")
            sys.exit(1)
        validate_new_passphrase(pw)
        save_wrapped_key(key, pw)
        print("Saved hardware-wrapped key with passphrase gate.")
    elif opt == "3":
        token = read_unlock_token()
        if not token:
            print("No token. Leave proot, run bash naza_unlock.sh after termux-keystore generate, then come back and pick 3.")
            sys.exit(1)
        save_wrapped_key(key, token)
        consume_unlock_token()
        print("Saved key gated by fingerprint token. Unlock from Termux before each boot.")
    else:
        print("Invalid key-protection choice; no key was created.")
        sys.exit(1)
    return key

def verify_model_integrity(path: Path, expected_sha: str = EXPECTED_HASH) -> str:
 
    if not path.exists():
        raise FileNotFoundError(f"model not found: {path}")
    if _is_symlink(path):
        raise RuntimeError("model path is a symlink")
    sha = sha256_file(path)
    if not hmac.compare_digest(sha.lower(), expected_sha.lower()):
        raise ValueError(f"model SHA256 mismatch: expected {expected_sha}, got {sha}")
    return sha


def download_model_httpx(url: str, dest: Path, show_progress=True, timeout=None, expected_sha: Optional[str]=None):
    print(f"Downloading model from {url}\nTo: {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if _is_symlink(dest):
        raise RuntimeError("model path is a symlink")
    tmp = dest.with_name(dest.name + "." + secrets.token_hex(8) + ".part")
    h = hashlib.sha256()
    try:
        request_timeout = timeout if timeout is not None else httpx.Timeout(300.0, connect=30.0)
        with httpx.stream("GET", url, follow_redirects=True, timeout=request_timeout) as r:
            r.raise_for_status()
            if r.url.scheme != "https":
                raise ValueError("model download redirected outside HTTPS")
            total = int(r.headers.get("Content-Length") or 0)
            if total < 0 or total > MAX_MODEL_DOWNLOAD:
                raise ValueError("model download exceeds the configured size limit")
            done = 0
            with tmp.open("wb") as f:
                for chunk in r.iter_bytes(chunk_size=8192):
                    if not chunk: break
                    f.write(chunk)
                    h.update(chunk)
                    done += len(chunk)
                    if done > MAX_MODEL_DOWNLOAD:
                        raise ValueError("model download exceeds the configured size limit")
                    if total and show_progress:
                        pct = done / total * 100
                        bar = int(pct // 2)
                        sys.stdout.write(f"\r[{('#'*bar).ljust(50)}] {pct:5.1f}% ({done//1024}KB/{total//1024}KB)")
                        sys.stdout.flush()
        if show_progress: print("\nDownload complete.")
        sha = h.hexdigest()
        print(f"SHA256: {sha}")
        if expected_sha and not hmac.compare_digest(sha.lower(), expected_sha.lower()):
            raise ValueError(f"model SHA256 mismatch: expected {expected_sha}, got {sha}")

        os.replace(str(tmp), str(dest))
        _chmod_private(dest)
        if expected_sha:
            print(color("SHA256 matches expected.", fg=32, bold=True))
        return sha, True
    except Exception:
        try:
            if tmp.exists():
                secure_unlink(tmp)
        except Exception:
            try:
                tmp.unlink()
            except Exception:
                pass
        raise

def encrypt_file(src: Path, dest: Path, key: bytes):
    print(f"🔐 Encrypting {src} -> {dest}")
    _assert_private_regular(src, "plaintext input")
    data = storage.read_private(src)
    start = time.time()
    enc = aes_encrypt(data, key)
    _atomic_write_private(dest, enc)
    write_file_mac(dest, key)
    dur = time.time()-start
    print(f"Encrypted ({len(enc)} bytes) in {dur:.2f}s")

def decrypt_file(src: Path, dest: Path, key: bytes):
    print(f"Decrypting {src} -> {dest}")
    _assert_private_regular(src, "encrypted input")
    macp = Path(str(src) + MAC_SUFFIX)
    if macp.exists() and not verify_file_mac(src, key):
        raise ValueError("encrypted file MAC check failed")
    enc = storage.read_private(src)
    data = aes_decrypt(enc, key)
    _atomic_write_private(dest, data)
    if not macp.exists():
        write_file_mac(src, key)
    print(f"Decrypted ({len(data)} bytes)")

def _history_temp() -> Path:
    return PRIVATE_TMP_DIR / (secrets.token_hex(10) + ".db")


def cleanup_private_temps():
    storage.private_directory(PRIVATE_TMP_DIR)
    for path in PRIVATE_TMP_DIR.iterdir():
        secure_unlink(path)
        if os.path.lexists(str(path)):
            raise RuntimeError("Could not remove private temporary artifact: {}".format(path))


async def init_db(key: bytes):
    if DB_PATH.exists():
        _assert_private_regular(DB_PATH, "encrypted history")
        macp = Path(str(DB_PATH) + MAC_SUFFIX)
        if macp.exists() and not verify_file_mac(DB_PATH, key):
            raise ValueError("encrypted history MAC check failed")
        aes_decrypt(storage.read_private(DB_PATH), key)
        if not macp.exists():
            write_file_mac(DB_PATH, key)
        return
    dec = _history_temp()
    try:
        async with aiosqlite.connect(dec) as db:
            await db.execute("CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, prompt TEXT, response TEXT)")
            await db.commit()
        write_private = storage.read_private(dec)
        _atomic_write_private(DB_PATH, aes_encrypt(write_private, key))
        write_file_mac(DB_PATH, key)
    finally:
        secure_unlink(dec)

async def log_interaction(prompt: str, response: str, key: bytes):
    dec = _history_temp()
    try:
        decrypt_file(DB_PATH, dec, key)
        async with aiosqlite.connect(dec) as db:
            await db.execute("INSERT INTO history (timestamp, prompt, response) VALUES (?, ?, ?)", (time.strftime("%Y-%m-%d %H:%M:%S"), prompt, response))
            await db.commit()
        _atomic_write_private(DB_PATH, aes_encrypt(dec.read_bytes(), key))
        write_file_mac(DB_PATH, key)
    finally:
        secure_unlink(dec)

async def fetch_history(key: bytes, limit:int=20, offset:int=0, search:Optional[str]=None):
    dec = _history_temp()
    try:
        decrypt_file(DB_PATH, dec, key)
        rows=[]
        async with aiosqlite.connect(dec) as db:
            if search:
                q = f"%{search}%"
                async with db.execute("SELECT id,timestamp,prompt,response FROM history WHERE prompt LIKE ? OR response LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?", (q,q,limit,offset)) as cur:
                    async for r in cur: rows.append(r)
            else:
                async with db.execute("SELECT id,timestamp,prompt,response FROM history ORDER BY id DESC LIMIT ? OFFSET ?", (limit,offset)) as cur:
                    async for r in cur: rows.append(r)
        return rows
    finally:
        secure_unlink(dec)

def load_llama_model_blocking(model_path: Path) -> Llama:
    verify_model_integrity(model_path)
    return Llama(model_path=str(model_path), n_ctx=2048, n_threads=4)

def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception:
        return None


def _nproc() -> int:
    try:
        n = os.cpu_count()
        if n and n > 0:
            return int(n)
    except Exception:
        pass
    raw = _read_text("/proc/cpuinfo")
    if raw:
        n = sum(1 for line in raw.splitlines() if line.startswith("processor"))
        if n:
            return n
    return 1


def _read_proc_stat():

    raw = _read_text("/proc/stat")
    if not raw:
        return None
    line = None
    for ln in raw.splitlines():
        if ln.startswith("cpu ") or ln.startswith("cpu\t"):
            line = ln
            break
    if not line:
        return None
    try:
        vals = [int(x) for x in line.split()[1:]]
    except Exception:
        return None
    if len(vals) < 4:
        return None
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    return sum(vals), idle


def _cpu_percent_from_proc(sample_interval=0.15):

    t1 = _read_proc_stat()
    if not t1:
        return None
    time.sleep(sample_interval)
    t2 = _read_proc_stat()
    if not t2:
        return None
    total_delta = t2[0] - t1[0]
    idle_delta = t2[1] - t1[1]
    if total_delta <= 0:
        return None
    return max(0.0, min(1.0, (total_delta - idle_delta) / float(total_delta)))


def _cpu_from_uptime():

    raw = _read_text("/proc/uptime")
    if not raw:
        return None
    try:
        parts = raw.split()
        uptime = float(parts[0])
        idle = float(parts[1]) if len(parts) > 1 else 0.0
        n = float(max(1, _nproc()))
        if uptime <= 0:
            return None
        busy = 1.0 - (idle / (uptime * n))
        return max(0.0, min(1.0, busy))
    except Exception:
        return None


def _cpu_from_load():
    return _load1_from_proc()


def _psi_cpu_some() -> Optional[float]:

    raw = _read_text("/proc/pressure/cpu")
    if not raw:
        return None
    try:
        for line in raw.splitlines():
            if line.startswith("some"):
                for tok in line.split():
                    if tok.startswith("avg10="):
                        return max(0.0, min(1.0, float(tok.split("=", 1)[1]) / 100.0))
    except Exception:
        return None
    return None


def _mem_from_proc():

    raw = _read_text("/proc/meminfo")
    if not raw:
        return None
    info = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        k, rest = line.split(":", 1)
        try:
            info[k.strip()] = int(rest.strip().split()[0])
        except Exception:
            continue
    total = info.get("MemTotal")
    if not total:
        return None
    available = info.get("MemAvailable")
    if available is None:
        available = info.get("MemFree", 0) + info.get("Buffers", 0) + info.get("Cached", 0)
    return max(0.0, min(1.0, (total - available) / float(total)))


def _load1_from_proc():

    raw = _read_text("/proc/loadavg")
    if not raw:
        return None
    try:
        parts = raw.split()
        load1 = float(parts[0])
        return max(0.0, min(1.0, load1 / float(max(1, _nproc()))))
    except Exception:
        return None


def _proc_count_from_proc():

    raw = _read_text("/proc/loadavg")
    total_tasks = None
    if raw:
        try:
            frac = raw.split()[3]  # e.g. 2/184
            total_tasks = int(frac.split("/")[1])
        except Exception:
            total_tasks = None
    if total_tasks is None:
        try:
            total_tasks = sum(1 for name in os.listdir("/proc") if name.isdigit())
        except Exception:
            return None
    return max(0.0, min(1.0, total_tasks / 400.0))


def _milli_to_c(raw: str) -> Optional[float]:
    try:
        val = int(raw.strip())
    except Exception:
        return None
    return val / 1000.0 if abs(val) > 200 else float(val)


def _read_temperature():

    preferred_types = (
        "x86_pkg_temp", "cpu-thermal", "soc_thermal", "acpitz",
        "cpu", "k10temp", "coretemp",
    )
    temps = []
    preferred = []
    base = "/sys/class/thermal"
    try:
        if os.path.isdir(base):
            for entry in os.listdir(base):
                if not entry.startswith("thermal_zone"):
                    continue
                z = os.path.join(base, entry)
                t = _read_text(os.path.join(z, "temp"))
                if not t:
                    continue
                c = _milli_to_c(t)
                if c is None:
                    continue
                typ = (_read_text(os.path.join(z, "type")) or "").strip().lower()
                if any(p in typ for p in preferred_types):
                    preferred.append(c)
                else:
                    temps.append(c)
    except Exception:
        pass
    if not preferred and not temps:
        hwmon = "/sys/class/hwmon"
        try:
            if os.path.isdir(hwmon):
                for entry in os.listdir(hwmon):
                    d = os.path.join(hwmon, entry)
                    for name in os.listdir(d):
                        if name.startswith("temp") and name.endswith("_input"):
                            t = _read_text(os.path.join(d, name))
                            if t:
                                c = _milli_to_c(t)
                                if c is not None:
                                    temps.append(c)
        except Exception:
            pass
    pool = preferred or temps
    if not pool:
        return None
    avg_c = sum(pool) / len(pool)
    return max(0.0, min(1.0, (avg_c - 20.0) / 70.0))


def collect_system_metrics() -> Dict[str, float]:
    cpu = _cpu_percent_from_proc()
    if cpu is None:
        cpu = _psi_cpu_some()
    if cpu is None:
        cpu = _cpu_from_uptime()
    if cpu is None:
        cpu = _cpu_from_load()
    psi = _psi_cpu_some()
    if cpu is not None and psi is not None:
        cpu = max(0.0, min(1.0, 0.7 * cpu + 0.3 * psi))

    mem = _mem_from_proc()
    load1 = _load1_from_proc()
    proc = _proc_count_from_proc()
    temp = _read_temperature()

    defaults = {"cpu": 0.12, "mem": 0.20, "load1": 0.10, "proc": 0.08, "temp": 0.25}
    if cpu is None:
        cpu = defaults["cpu"]
    if mem is None:
        mem = defaults["mem"]
    if load1 is None:
        load1 = defaults["load1"]
    if proc is None:
        proc = defaults["proc"]
    if temp is None:
        temp = defaults["temp"]

    return {
        "cpu": float(max(0.0, min(1.0, cpu))),
        "mem": float(max(0.0, min(1.0, mem))),
        "load1": float(max(0.0, min(1.0, load1))),
        "proc": float(max(0.0, min(1.0, proc))),
        "temp": float(max(0.0, min(1.0, temp))),
    }


_WOBBLE_HIST: List[Tuple[float, Dict[str, float]]] = []
_WOBBLE_MAX = 12
_WOBBLE_WORDS = ("still", "drift", "swell", "chop", "surge", "break")
_WOBBLE_LEADERS = ("cpu", "mem", "load1", "temp", "proc")


def measure_wobble(metrics: dict) -> dict:

    now = time.time()
    keys = ("cpu", "mem", "load1", "temp", "proc")
    snap = {k: float(metrics.get(k, 0.0)) for k in keys}
    _WOBBLE_HIST.append((now, snap))
    del _WOBBLE_HIST[:-_WOBBLE_MAX]
    n = len(_WOBBLE_HIST)

    def _rms_speed(hist):
        if len(hist) < 2:
            return 0.0
        acc = 0.0
        for i in range(1, len(hist)):
            t0, a = hist[i - 1]
            t1, b = hist[i]
            dt = max(1e-3, t1 - t0)
            acc += math.sqrt(sum((b[k] - a[k]) ** 2 for k in keys) / 5.0) / dt
        return acc / (len(hist) - 1)

    fast = _clamp01(_rms_speed(_WOBBLE_HIST[-3:]) * 0.40)
    slow = _clamp01(_rms_speed(_WOBBLE_HIST) * 0.28)
    jerk = _clamp01(abs(fast - slow) * 1.4)

    flips = 0
    prev = None
    for _, s in _WOBBLE_HIST:
        sig = 1 if s["cpu"] + s["load1"] >= s["mem"] + s["temp"] else -1
        if prev is not None and sig != prev:
            flips += 1
        prev = sig
    rate = _clamp01(flips / max(1, n - 1))

    mean = {k: sum(s[k] for _, s in _WOBBLE_HIST) / n for k in keys}
    last = _WOBBLE_HIST[-1][1]
    num = sum(last[k] * mean[k] for k in keys)
    den = math.sqrt(sum(last[k] ** 2 for k in keys) * sum(mean[k] ** 2 for k in keys)) or 1.0
    coh = _clamp01((num / den + 1.0) * 0.5)

    travel = {}
    if n >= 2:
        first = _WOBBLE_HIST[0][1]
        travel = {k: abs(last[k] - first[k]) for k in keys}
    else:
        travel = {k: 0.0 for k in keys}
    leader = max(keys, key=lambda k: travel[k])
    phase = (math.atan2(last["cpu"] - last["mem"], last["load1"] - last["temp"] + 1e-9) / (2.0 * math.pi)) % 1.0

    amp = _clamp01(0.55 * fast + 0.30 * slow + 0.15 * jerk)
    level = min(5, int((amp * 0.50 + rate * 0.20 + jerk * 0.15 + (1.0 - coh) * 0.15) * 6))
    word = _WOBBLE_WORDS[level]
    return {
        "amp": amp,
        "fast": fast,
        "slow": slow,
        "jerk": jerk,
        "rate": rate,
        "coh": coh,
        "level": level,
        "word": word,
        "phase": phase,
        "leader": leader,
        "travel": travel,
        "seed": int(phase * 997) + level * 13,
        "qcpu": last["cpu"],
        "qmem": last["mem"],
        "qload": last["load1"],
        "qtemp": last["temp"],
        "qproc": last["proc"],
    }


def wobble_announce(w: dict) -> str:
    return (
        f"wobble: {w['word']} lv={w['level']}/5 leader={w['leader']} "
        f"amp={w['amp']:.2f} fast={w['fast']:.2f} slow={w['slow']:.2f} jerk={w['jerk']:.2f} "
        f"rate={w['rate']:.2f} coh={w['coh']:.2f} phase={w['phase']:.2f}"
    )

def _c(re: float, im: float = 0.0) -> complex:
    return complex(re, im)


def _kron2(a, b):
    
    return a 


def _apply_1q(state, n, q, u00, u01, u10, u11):

    dim = 1 << n
    bit = 1 << q
    for i in range(dim):
        if i & bit:
            continue
        j = i | bit
        a, b = state[i], state[j]
        state[i] = u00 * a + u01 * b
        state[j] = u10 * a + u11 * b


def _rx(state, n, q, theta):
    c = math.cos(theta / 2.0)
    s = math.sin(theta / 2.0)
    _apply_1q(state, n, q, _c(c), _c(0, -s), _c(0, -s), _c(c))


def _ry(state, n, q, theta):
    c = math.cos(theta / 2.0)
    s = math.sin(theta / 2.0)
    _apply_1q(state, n, q, _c(c), _c(-s), _c(s), _c(c))


def _rz(state, n, q, theta):
    ph = theta / 2.0
    e_m = complex(math.cos(-ph), math.sin(-ph))
    e_p = complex(math.cos(ph), math.sin(ph))
    dim = 1 << n
    bit = 1 << q
    for i in range(dim):
        if i & bit:
            state[i] *= e_p
        else:
            state[i] *= e_m


def _h(state, n, q):
    s2 = math.sqrt(0.5)
    _apply_1q(state, n, q, _c(s2), _c(s2), _c(s2), _c(-s2))


def _cx(state, n, ctrl, tgt):
    dim = 1 << n
    cb, tb = 1 << ctrl, 1 << tgt
    for i in range(dim):
        if (i & cb) and not (i & tb):
            j = i | tb
            state[i], state[j] = state[j], state[i]


def _cz(state, n, a, b):
    dim = 1 << n
    mask = (1 << a) | (1 << b)
    for i in range(dim):
        if (i & mask) == mask:
            state[i] = -state[i]


def _exp_z(state, n, q) -> float:
    dim = 1 << n
    bit = 1 << q
    acc = 0.0
    for i, amp in enumerate(state):
        p = amp.real * amp.real + amp.imag * amp.imag
        acc += p if not (i & bit) else -p
    return acc


def _exp_zz(state, n, q, r) -> float:
    dim = 1 << n
    bq, br = 1 << q, 1 << r
    acc = 0.0
    for i, amp in enumerate(state):
        p = amp.real * amp.real + amp.imag * amp.imag
        sign = 1.0 if not ((bool(i & bq)) ^ (bool(i & br))) else -1.0
        acc += sign * p
    return acc


def _entropy_cut01(state, n) -> float:

    env = 1 << (n - 2)
    rho = [[0j] * 4 for _ in range(4)]
    for ab in range(4):
        for cd in range(4):
            s = 0j
            for k in range(env):
                ia = ab | (k << 2)
                ib = cd | (k << 2)
                s += state[ia] * state[ib].conjugate()
            rho[ab][cd] = s
    a = [[rho[i][j] for j in range(4)] for i in range(4)]
    for i in range(4):
        a[i][i] = complex(a[i][i].real, 0.0)
        for j in range(i + 1, 4):
            hij = 0.5 * (a[i][j] + a[j][i].conjugate())
            a[i][j] = hij
            a[j][i] = hij.conjugate()
    v = [[_c(1.0 if i == j else 0.0) for j in range(4)] for i in range(4)]
    for _ in range(24):
        for p in range(3):
            for q in range(p + 1, 4):
                app, aqq = a[p][p].real, a[q][q].real
                apq = a[p][q]
                if abs(apq) < 1e-15:
                    continue
                tau = (aqq - app) / (2.0 * abs(apq) if abs(apq) else 1.0)
                t = math.copysign(1.0, tau) / (abs(tau) + math.sqrt(1.0 + tau * tau))
                c = 1.0 / math.sqrt(1.0 + t * t)
                s = t * c
                phase = apq / abs(apq) if abs(apq) else 1+0j
                for k in range(4):
                    aik, aiq = a[k][p], a[k][q]
                    a[k][p] = c * aik - s * phase.conjugate() * aiq
                    a[k][q] = s * phase * aik + c * aiq
                for k in range(4):
                    akp, akq = a[p][k], a[q][k]
                    a[p][k] = c * akp - s * phase * akq
                    a[q][k] = s * phase.conjugate() * akp + c * akq
    eigs = [max(0.0, a[i][i].real) for i in range(4)]
    tot = sum(eigs) or 1.0
    eigs = [e / tot for e in eigs]
    ent = 0.0
    for e in eigs:
        if e > 1e-12:
            ent -= e * math.log(e)
    return max(0.0, min(1.0, ent / math.log(4.0)))


BAND_NAMES = (
    "infra", "crimson", "vermilion", "amber", "gold", "chartreuse",
    "viridian", "teal", "azure", "cobalt", "violet", "ultraviolet",
)
BAND_COUNT = len(BAND_NAMES)


def _clamp01(x: float) -> float:
    x = float(x)
    if not math.isfinite(x):
        raise ValueError("circuit metrics must be finite")
    return float(max(0.0, min(1.0, x)))


def _circuit_metrics(metrics: dict) -> dict:
    if not isinstance(metrics, dict):
        raise TypeError("circuit metrics must be a mapping")
    return {name: _clamp01(metrics.get(name, 0.0))
            for name in ("cpu", "mem", "load1", "temp", "proc")}


def _hsv_to_rgb(h: float, s: float, v: float) -> Tuple[float, float, float]:
    h = h % 1.0
    i = int(h * 6.0)
    f = h * 6.0 - i
    p = v * (1.0 - s)
    q = v * (1.0 - f * s)
    t = v * (1.0 - (1.0 - f) * s)
    i %= 6
    if i == 0: r, g, b = v, t, p
    elif i == 1: r, g, b = q, v, p
    elif i == 2: r, g, b = p, v, t
    elif i == 3: r, g, b = p, q, v
    elif i == 4: r, g, b = t, p, v
    else:        r, g, b = v, p, q
    return _clamp01(r), _clamp01(g), _clamp01(b)


def _wrap_dist(a: float, b: float) -> float:
    d = abs((a - b) % 1.0)
    return min(d, 1.0 - d)


def metrics_to_rainbow(metrics: dict) -> dict:

    metrics = _circuit_metrics(metrics)
    cpu, mem, load1, temp, proc = (metrics[name] for name in
                                    ("cpu", "mem", "load1", "temp", "proc"))
    channels = {
        "cpu":   (cpu,   0.00, 0.070),
        "mem":   (mem,   0.18, 0.065),
        "load1": (load1, 0.36, 0.080),
        "temp":  (temp,  0.58, 0.055),
        "proc":  (proc,  0.78, 0.075),
    }
    spectrum = [0.0] * BAND_COUNT
    channel_hues = {}
    xs = ys = 0.0
    for name, (mag, offset, sigma) in channels.items():
        h = (offset + 0.28 * mag + 0.10 * mag * mag + 0.05 * load1 * mag) % 1.0
        channel_hues[name] = h
        w = 0.18 + 0.82 * mag
        ang = 2.0 * math.pi * h
        xs += w * math.cos(ang)
        ys += w * math.sin(ang)
        for i in range(BAND_COUNT):
            center = (i + 0.5) / BAND_COUNT
            d = _wrap_dist(center, h)
            spectrum[i] += mag * math.exp(-0.5 * (d / sigma) ** 2)
    ssum = sum(spectrum) or 1.0
    spectrum = [x / ssum for x in spectrum]
    cx = cy = 0.0
    for i, p in enumerate(spectrum):
        ang = 2.0 * math.pi * ((i + 0.5) / BAND_COUNT)
        cx += p * math.cos(ang)
        cy += p * math.sin(ang)
    hue = (math.atan2(cy, cx) / (2.0 * math.pi)) % 1.0
    R = math.hypot(cx, cy)
    spread = _clamp01(1.0 - R)
    peak = max(spectrum)
    mean_p = 1.0 / BAND_COUNT
    lock = _clamp01((peak - mean_p) / (1.0 - mean_p))
    stress = (cpu + mem + load1 + temp + proc) / 5.0
    rough = 0.0
    for i in range(BAND_COUNT):
        rough += abs(spectrum[i] - spectrum[(i + 1) % BAND_COUNT])
    rough = _clamp01(rough / 2.0)
    sat = _clamp01(0.28 + 0.55 * stress + 0.17 * (1.0 - spread))
    val = _clamp01(0.38 + 0.40 * stress + 0.22 * lock)
    r, g, b = _hsv_to_rgb(hue, sat, val)
    band_idx = max(range(BAND_COUNT), key=lambda i: spectrum[i])
    band_frac = _clamp01(spectrum[band_idx] * BAND_COUNT - (BAND_COUNT - 1) * mean_p)
    ranked = sorted(range(BAND_COUNT), key=lambda i: spectrum[i], reverse=True)
    top3 = [(BAND_NAMES[i], spectrum[i]) for i in ranked[:3]]
    neighbors = (
        BAND_NAMES[(band_idx - 1) % BAND_COUNT],
        BAND_NAMES[band_idx],
        BAND_NAMES[(band_idx + 1) % BAND_COUNT],
    )
    warm = sum(spectrum[i] for i in range(0, 6))
    cool = 1.0 - warm
    wob = measure_wobble(metrics)
    leader_h = channel_hues.get(wob["leader"], hue)
    if wob["amp"] > 0.04:
        shifted = [0.0] * BAND_COUNT
        shift = int(round(wob["phase"] * wob["amp"] * 2.0)) % BAND_COUNT
        for i, p in enumerate(spectrum):
            li = int(leader_h * BAND_COUNT) % BAND_COUNT
            dest = (i + shift) % BAND_COUNT
            pulled = p * (0.18 * wob["amp"])
            shifted[dest] += p - pulled
            shifted[li] += pulled
        ssum = sum(shifted) or 1.0
        spectrum = [x / ssum for x in shifted]
    return {
        "hue": hue,
        "sat": sat,
        "val": val,
        "lock": lock,
        "spread": spread,
        "rough": rough,
        "rgb": (r, g, b),
        "band_idx": band_idx,
        "band_name": BAND_NAMES[band_idx],
        "band_frac": band_frac,
        "neighbors": neighbors,
        "channel_hues": channel_hues,
        "stress": stress,
        "spectrum": spectrum,
        "top3": top3,
        "warm": warm,
        "cool": cool,
        "centroid_R": R,
        "wobble": wob,
    }


def rainbow_prompt_line(sync: dict) -> str:
    r, g, b = sync["rgb"]
    spec = sync.get("spectrum") or []
    spec_s = ",".join(f"{BAND_NAMES[i][:3]}:{p:.2f}" for i, p in enumerate(spec))
    top = sync.get("top3") or []
    top_s = "+".join(f"{n}:{p:.2f}" for n, p in top)
    return (
        f"color_sync: hue={sync['hue']:.3f} sat={sync['sat']:.3f} val={sync['val']:.3f} "
        f"lock={sync['lock']:.3f} spread={sync.get('spread',0):.3f} rough={sync.get('rough',0):.3f} "
        f"warm={sync.get('warm',0):.2f} cool={sync.get('cool',0):.2f} "
        f"rgb=({r:.2f},{g:.2f},{b:.2f}) "
        f"peak={sync['band_name']}({sync['band_idx']}/12) frac={sync['band_frac']:.3f} "
        f"top3={top_s} spectrum=[{spec_s}] "
        + (wobble_announce(sync["wobble"]) if sync.get("wobble") else "")
    )


def house_entropic_score(metrics: dict) -> Tuple[float, dict]:
 
    metrics = _circuit_metrics(metrics)
    sync = metrics_to_rainbow(metrics)
    feats = [
        float(metrics.get("cpu", 0.0)),
        float(metrics.get("mem", 0.0)),
        float(metrics.get("load1", 0.0)),
        float(metrics.get("temp", 0.0)),
        float(metrics.get("proc", 0.0)),
    ]
    n = 5
    state = [0j] * (1 << n)
    state[0] = 1+0j
    hue, sat, val = sync["hue"], sync["sat"], sync["val"]
    band, frac, lock = sync["band_idx"], sync["band_frac"], sync["lock"]
    r, g, bcol = sync["rgb"]
    spec = sync["spectrum"]
    warm, cool, spread, rough = sync["warm"], sync["cool"], sync["spread"], sync["rough"]
    ch = sync["channel_hues"]
    ch_list = [ch.get(k, 0.0) for k in ("cpu", "mem", "load1", "temp", "proc")]

    topologies = (
        [(0, 1), (1, 2), (2, 3), (3, 4)],
        [(2, 0), (2, 1), (2, 3), (2, 4)],
        [(0, 1), (1, 2), (2, 3), (3, 4), (4, 0)],
        [(0, 1), (2, 3), (1, 2), (3, 4)],
        [(0, 2), (1, 3), (2, 4), (0, 3)],
        [(0, 1), (0, 2), (1, 3), (2, 4), (3, 4)],
    )

    for q, x in enumerate(feats):
        _h(state, n, q)
        _ry(state, n, q, x * math.pi * (0.7 + 0.3 * spec[q % BAND_COUNT]))
        _rz(state, n, q, ch_list[q] * 2.0 * math.pi)
        _rx(state, n, q, (1.0 - x) * math.pi * 0.45)

    def _layer(pairs, energy, tint_r, tint_g, tint_b, reverse=False):
        seq = list(reversed(pairs)) if reverse else pairs
        for a, c in seq:
            _cx(state, n, a, c)
            if energy > 0.12:
                _cz(state, n, a, c)
        for q, x in enumerate(feats):
            y = feats[(q + 1) % n]
            e_local = spec[(band + q) % BAND_COUNT]
            _rx(state, n, q, (x * y * tint_r + e_local * energy) * math.pi)
            _ry(state, n, q, (abs(x - y) * tint_g + frac * energy) * math.pi)
            _rz(state, n, q, tint_b * val * energy * math.pi)

    _layer(topologies[band % 6], warm * (0.6 + 0.4 * lock), r, g, bcol, reverse=False)
    _layer(topologies[(band + 2) % 6], spec[band] * (0.5 + 0.5 * sat), g, bcol, r, reverse=True)
    _layer(topologies[(band + 4) % 6], cool * (0.5 + 0.5 * spread), bcol, r, g, reverse=False)

    if rough > 0.05:
        for q in range(n):
            _rz(state, n, q, rough * (q + 1) * math.pi / n)

    wob = sync.get("wobble") or measure_wobble(metrics)
    lead_q = {"cpu": 0, "mem": 1, "load1": 2, "temp": 3, "proc": 4}.get(wob["leader"], 0)
    for q in range(n):
        _rz(state, n, q, wob["phase"] * 2.0 * math.pi * (0.25 + 0.75 * wob["slow"]))
        _rx(state, n, q, wob["fast"] * math.pi * 0.30)
        _ry(state, n, q, wob["jerk"] * math.pi * 0.20)
    for t in range(n):
        if t != lead_q:
            _cx(state, n, lead_q, t)
            if wob["level"] >= 3:
                _cz(state, n, lead_q, t)

    norm = sum(amp.real * amp.real + amp.imag * amp.imag for amp in state)
    if not math.isfinite(norm) or abs(norm - 1.0) > 1e-9:
        raise RuntimeError("circuit state normalization check failed")

    topology = band % 6

    zs = [_exp_z(state, n, q) for q in range(n)]
    zzs = []
    for i in range(n):
        for j in range(i + 1, n):
            zzs.append(_exp_zz(state, n, i, j))
    cut_s = _entropy_cut01(state, n)

    excite = [(1.0 - z) * 0.5 for z in zs]
    tension = sum((1.0 - zz) * 0.5 for zz in zzs) / max(1, len(zzs))
    w = [0.28, 0.22, 0.20, 0.16, 0.14]
    stress = sum(wi * ei for wi, ei in zip(w, excite))
    raw = 0.45 * stress + 0.25 * tension + 0.30 * cut_s
    score = 1.0 / (1.0 + math.exp(-8.0 * (raw - 0.42)))
    score = float(max(0.0, min(1.0, score)))
    if not all(math.isfinite(x) for x in zs + zzs + [cut_s, tension, raw, score]):
        raise RuntimeError("circuit produced a non-finite observable")
    transcript = json.dumps(
        {"v": 1, "metrics": metrics, "band": band, "topology": topology,
         "z": [round(x, 12) for x in zs], "zz": [round(x, 12) for x in zzs],
         "entropy": round(cut_s, 12), "score": round(score, 12)},
        sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("ascii")
    circuit_digest = hashlib.sha256(b"NAZA-CIRCUIT-V1\x00" + transcript).hexdigest()
    sync["circuit_digest"] = circuit_digest
    detail = {
        "z": zs,
        "excite": excite,
        "tension": tension,
        "cut_entropy": cut_s,
        "raw": raw,
        "score": score,
        "sync": sync,
        "topology": topology,
        "band": sync["band_name"],
        "circuit_digest": circuit_digest,
    }
    return score, detail


def pennylane_entropic_score(rgb_or_metrics, shots: int = 256) -> float:

    if isinstance(rgb_or_metrics, dict):
        s, _ = house_entropic_score(rgb_or_metrics)
        return s
    r, g, b = rgb_or_metrics
    dummy = {"cpu": float(r), "mem": float(g), "load1": float(r), "temp": float(b), "proc": float(g)}
    s, _ = house_entropic_score(dummy)
    return s

def entropic_to_modifier(score: float) -> float:
    return (score - 0.5) * 0.4

def seal_scan(label: str, prompt: str, sync: Optional[dict], key: bytes) -> str:
    lock = ""
    wob = ""
    circuit = ""
    if sync:
        raw_lock = sync.get("lock")
        if isinstance(raw_lock, (list, tuple)):
            lock = ",".join(str(item) for item in raw_lock)
        elif raw_lock is not None:
            lock = "{:.3f}".format(float(raw_lock))
        w = sync.get("wobble") or {}
        wob = "{}:{}".format(w.get("word", ""), w.get("leader", ""))
        digest = str(sync.get("circuit_digest", ""))
        if digest:
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("invalid circuit transcript digest")
            circuit = digest
    body = "|".join([label, lock, wob, circuit, hashlib.sha256((prompt or "").encode()).hexdigest()[:16]])
    tag = hmac.new(_mac_key(key), body.encode(), hashlib.sha256).hexdigest()[:24]
    return "receipt {} {}".format(body, tag)


def persist_scan_receipt(label: str, prompt: str, sync: Optional[dict], key: bytes) -> str:

    global _LAST_RECEIPT
    receipt = seal_scan(label, prompt, sync, key)
    _atomic_write_private(Path("naza.last.receipt"), (receipt + "\n").encode())
    _LAST_RECEIPT = receipt
    return receipt


def entropic_summary_text(score: float) -> str:
    if score >= 0.75: level = "high"
    elif score >= 0.45: level = "medium"
    else: level = "low"
    return f"entropic_score={score:.3f} (level={level})"

def _simple_tokenize(text: str) -> List[str]:
    return [t for t in re.findall(r"[A-Za-z0-9_\-]+", text.lower())]

def punkd_analyze(prompt_text: str, top_n: int = 12) -> Dict[str,float]:
    toks = _simple_tokenize(prompt_text)
    freq={}
    for t in toks: freq[t]=freq.get(t,0)+1
    hazard_boost = {"ice":2.0,"wet":1.8,"snow":2.0,"flood":2.0,"construction":1.8,"pedestrian":1.8,"debris":1.8,"animal":1.5,"stall":1.4,"fog":1.6}
    scored={}
    for t,c in freq.items():
        boost = hazard_boost.get(t,1.0)
        scored[t]=c*boost
    items = sorted(scored.items(), key=lambda x:-x[1])[:top_n]
    if not items: return {}
    maxv = items[0][1]
    return {k: float(v/maxv) for k,v in items}

def punkd_apply(prompt_text: str, token_weights: Dict[str,float], profile: str = "balanced") -> Tuple[str,float]:
    if not token_weights: return prompt_text, 1.0
    mean_weight = sum(token_weights.values())/len(token_weights)
    profile_map = {"conservative": 0.6, "balanced": 1.0, "aggressive": 1.4}
    base = profile_map.get(profile, 1.0)
    multiplier = 1.0 + (mean_weight - 0.5) * 0.8 * (base if base>1.0 else 1.0)
    multiplier = max(0.6, min(1.8, multiplier))
    sorted_tokens = sorted(token_weights.items(), key=lambda x:-x[1])[:6]
    markers = " ".join([f"<ATTN:{t}:{round(w,2)}>" for t,w in sorted_tokens])
    patched = prompt_text + "\n\n[PUNKD_MARKERS] " + markers
    return patched, multiplier

def chunked_generate(llm: Llama, prompt: str, max_total_tokens: int = 256, chunk_tokens: int = 64, base_temperature: float = 0.2, punkd_profile: str = "balanced", streaming_callback: Optional[Callable[[str], None]] = None) -> str:
    if max_total_tokens < 1 or chunk_tokens < 1:
        raise ValueError("token budgets must be positive")
    assembled = ""
    cur_prompt = prompt
    token_weights = punkd_analyze(prompt, top_n=16)
    iterations = max(1, (max_total_tokens + chunk_tokens - 1)//chunk_tokens)
    prev_tail = ""
    for i in range(iterations):
        patched_prompt, mult = punkd_apply(cur_prompt, token_weights, profile=punkd_profile)
        temp = max(0.01, min(2.0, base_temperature * mult))
        remaining = max_total_tokens - i * chunk_tokens
        out = llm(patched_prompt, max_tokens=min(chunk_tokens, remaining), temperature=temp)
        text = ""
        if isinstance(out, dict):
            try: text = out.get("choices",[{"text":""}])[0].get("text","")
            except Exception:
                text = out.get("text","") if isinstance(out, dict) else ""
        else:
            try: text = str(out)
            except Exception: text = ""
        text = (text or "").strip()
        if not text: break
        overlap = 0
        max_ol = min(30, len(prev_tail), len(text))
        for olen in range(max_ol, 0, -1):
            if prev_tail.endswith(text[:olen]):
                overlap = olen
                break
        append_text = text[overlap:] if overlap else text
        assembled += append_text
        prev_tail = assembled[-120:] if len(assembled)>120 else assembled
        if streaming_callback: streaming_callback(append_text)
        if assembled.strip().endswith(("Low","Medium","High")): break
        if len(text.split()) < max(4, chunk_tokens//8): break
        cur_prompt = prompt + "\n\nAssistant so far:\n" + assembled + "\n\nContinue:"
    return assembled.strip()

_LAST_SYNC: Optional[dict] = None
_LAST_RECEIPT: str = ""


def build_road_scanner_prompt(data: dict, include_system_entropy: bool = True) -> str:
    global _LAST_SYNC
    entropy_text = "entropic_score=unknown"
    if include_system_entropy:
        metrics = collect_system_metrics()
        score, qdetail = house_entropic_score(metrics)
        sync = qdetail.get("sync") or metrics_to_rainbow(metrics)
        _LAST_SYNC = sync
        entropy_text = (
            entropic_summary_text(score)
            + f" cutS={qdetail['cut_entropy']:.3f} tension={qdetail['tension']:.3f}"
            + " " + rainbow_prompt_line(sync)
            + f" band_circuit={qdetail.get('band','?')} topo={qdetail.get('topology','?')}"
        )
        wob = (sync.get("wobble") if sync else None) or measure_wobble(metrics)
        metrics_line = (
            "sys_metrics: cpu={cpu:.2f},mem={mem:.2f},load={load1:.2f},temp={temp:.2f},proc={proc:.2f}".format(
                cpu=metrics.get("cpu", 0.0),
                mem=metrics.get("mem", 0.0),
                load1=metrics.get("load1", 0.0),
                temp=metrics.get("temp", 0.0),
                proc=metrics.get("proc", 0.0),
            )
        )
    else:
        metrics_line = "sys_metrics: disabled"
    tpl = (
f"You are a Hypertime Nanobot specialized Cancer Risk Prediction and Early Warning AI trained to evaluate patterns associated with possible elevated cancer risk from patient-reported information, health history, symptoms, lifestyle factors, environmental exposure information, available screening information, wearable / smartphone sensor observations, and contextual data.\n"
f"Analyze and Triple Check the available information for consistency, relevance, severity, persistence, clustering, known risk associations, and possible warning patterns, then determine the overall cancer risk classification represented by the supplied information. This is a risk-stratification signal and not a cancer diagnosis, pathology result, medical confirmation, or substitute for professional screening. You must never treat the classification as proof that cancer is present or absent.\n"
f"Your task is to detect whether the combined information represents a relatively Low, Medium, or High level of concern that may justify progressively stronger attention, screening consideration, or professional medical evaluation. Evaluate the entire pattern rather than relying on one isolated symptom or data point. Consider both supporting and conflicting evidence and avoid inventing information that was not supplied.\n"
f"Your reply must be only one word: Low, Medium, or High.\n\n"
f"[tuning]\n"
f"Patient / observation context:\n"
f"Location / activity / patient context: {data.get('location','unspecified')}\n"
f"Age, general health, family history, known risk factors, or demographic context: {data.get('road_type','unknown')}\n"
f"Current symptoms, unusual changes, duration, progression, previous findings, or recent events: {data.get('weather','none reported')}\n"
f"Physiological trends, weight changes, energy level, temperature, heart rate, wearable observations, or other measurable changes: {data.get('traffic','unknown')}\n"
f"Additional medical history, exposure information, tobacco/alcohol history, occupational/environmental risks, screening information, medications, chronic conditions, or other relevant factors: {data.get('obstacles','none reported')}\n"
f"Additional sensor / patient / contextual notes: {data.get('sensor_notes','none')}\n"
f"{metrics_line}\n"
f"Quantum State / NAZA auxiliary entropic signal: {entropy_text}\n"
f"[/tuning]\n\n"
f"Follow these strict rules when forming your decision:\n"
f"- Think through all supplied patient, symptom, history, exposure, screening, contextual, and sensor factors internally but do not reveal chain-of-thought or internal reasoning.\n"
f"- Treat the task as cancer-risk stratification and early-warning classification only. Do not internally or externally convert the result into a definitive diagnosis.\n"
f"- A Low classification means the supplied information contains relatively few concerning indicators, lacks a strong cluster of persistent warning signs, or is more consistent with lower apparent risk based solely on the provided information. Low must never be interpreted as 'cancer free' or as permission to ignore recommended routine screening.\n"
f"- A Medium classification means there are meaningful risk factors, persistent or unexplained symptoms, incomplete but concerning combinations of findings, significant family/history information, relevant exposures, screening abnormalities without strong confirmation, or enough uncertainty that medical follow-up or appropriate screening should reasonably be considered.\n"
f"- A High classification means the supplied information contains a strong cluster of concerning factors, substantial known risk history combined with suspicious changes, persistent or progressive unexplained symptoms, highly abnormal reported findings, concerning previous screening information, or multiple independent warning signals that substantially increase concern and justify prompt professional evaluation.\n"
f"- Do not classify High merely because one vague symptom exists. Look for severity, persistence, progression, combinations of findings, known major risk factors, and agreement between independent information sources.\n"
f"- Conversely, do not suppress a High classification merely because some measurements appear normal when the supplied history contains multiple strong warning indicators.\n"
f"- Evaluate unexplained persistent lumps or masses, unusual bleeding, persistent blood in stool or urine, major unexplained weight loss, persistent swallowing difficulty, persistent changes in bowel or bladder habits, changing skin lesions, persistent unexplained cough or hoarseness, unexplained neurological changes, prolonged unexplained pain, severe persistent fatigue, unusual lymph-node enlargement, recurrent unexplained fever, or other reported persistent abnormalities as potentially relevant warning signals when they are actually present in the supplied data.\n"
f"- Evaluate age, hereditary or family cancer history, previous cancer or precancerous findings, tobacco exposure, substantial alcohol exposure, ultraviolet exposure, occupational carcinogen exposure, radiation history, certain chronic inflammatory conditions, immunosuppression, relevant infection history, obesity or metabolic factors, screening history, and other supplied established risk factors according to their combined significance rather than as isolated deterministic rules.\n"
f"- Distinguish persistent or progressive abnormalities from temporary, mild, isolated, or clearly explained events whenever the supplied information allows that distinction.\n"
f"- Give greater internal weight to objective or clinician-reported abnormalities than to vague unsupported speculation, while still considering patient-reported symptoms seriously when they are persistent, progressive, severe, or clustered.\n"
f"- Missing information is uncertainty, not evidence of health. Never assume an unreported test, symptom, family history, imaging result, laboratory value, biopsy result, or screening result is normal.\n"
f"- Do not invent laboratory values, imaging findings, tumor markers, genetic variants, diagnoses, pathology findings, probabilities, survival rates, stages, tumor locations, or medical history that were not provided.\n"
f"- Do not claim that ordinary device CPU, memory, load, temperature, process count, quantum-state simulation, rainbow synchronization, entropic state, PUNKD attention markers, or any other NAZA computational telemetry is a clinically validated biomarker for cancer.\n"
f"- The NAZA system-entropic / quantum signal is auxiliary computational metadata only. It must never outweigh actual patient history, symptoms, known risk factors, screening information, or medical evidence. It may influence internal computational confidence only minimally and must never create a cancer-risk signal by itself.\n"
f"- If patient information and the NAZA auxiliary signal conflict, prioritize the medically relevant patient information.\n"
f"- Evaluate the relationship among age, history, duration, progression, symptom clustering, lifestyle, hereditary risk, environmental exposure, prior screening, and available measurements holistically.\n"
f"- Give additional concern to combinations of independent risk cues rather than simply counting every symptom equally.\n"
f"- Avoid false certainty. A Low result does not exclude cancer; Medium does not mean probable cancer; High does not confirm cancer. These labels describe only relative concern within this experimental classifier.\n"
f"- If information is ambiguous but contains several credible concerning indicators, use a conservative classification rather than automatically choosing Low.\n"
f"- If information is severely incomplete with no meaningful positive or negative evidence, prefer Medium over inventing reassurance or a diagnosis.\n"
f"- If obvious sensor-integrity problems, contradictory inputs, corrupted information, impossible measurements, or substantial missing context prevent reliable interpretation, increase uncertainty rather than pretending precision. Where the uncertainty could conceal meaningful risk, bias conservatively toward Medium rather than falsely reassuring with Low.\n"
f"- Select High when the combination of supplied information represents substantial concern requiring timely professional assessment, not merely because the word 'cancer' occurs in the input.\n"
f"- Select Low only when the available pattern is genuinely comparatively reassuring and lacks significant persistent, progressive, or clustered warning information.\n"
f"- Select Medium for the broad intermediate state where concern exists but the evidence does not justify the strongest classification, or where uncertainty itself materially limits reliable reassurance.\n"
f"- Never provide medication instructions, treatment selection, chemotherapy recommendations, radiation recommendations, surgery recommendations, or instructions to delay professional care.\n"
f"- Never claim that this model can detect microscopic disease, determine cancer stage, identify tumor genetics, interpret pathology with certainty, replace mammography, colonoscopy, Pap/HPV testing, CT screening, dermatologic examination, PSA evaluation, biopsy, imaging, laboratory testing, or evaluation by a qualified medical professional.\n"
f"- Internally Triple Check the final classification before responding: first evaluate individual risk cues, second evaluate interactions and clustering, and third compare the entire pattern against the Low / Medium / High definitions.\n"
f"- Choose only one risk level that best represents the entire supplied situation.\n"
f"- Output exactly one word, with no explanation, punctuation, percentage, diagnostic name, probability, disclaimer, label prefix, reasoning, or additional text.\n"
f"- The only valid outputs are: Low, Medium, High.\n\n"
f"[action]\n"
f"1) Parse the supplied information and separate patient context, established risk factors, symptoms, duration/progression information, screening information, exposures, physiological observations, and uncertain or missing information.\n"
f"2) Normalize conceptually comparable risk information without inventing numerical measurements that were not supplied.\n"
f"3) Identify major established risk factors and determine whether multiple independent risk factors are present simultaneously.\n"
f"4) Identify reported warning signs and distinguish transient or weak observations from persistent, progressive, recurrent, unexplained, severe, or clustered abnormalities.\n"
f"5) Examine interactions between history and current changes. A concerning symptom combined with substantial hereditary, exposure, previous-lesion, screening, or lifestyle risk should generally carry greater concern than either factor alone.\n"
f"6) Examine whether apparently reassuring information genuinely reduces risk or merely represents missing / unrelated information.\n"
f"7) Consider relevant objective screening or clinician-reported abnormalities more strongly when supplied, but never infer a diagnosis beyond the information provided.\n"
f"8) Map the combined cancer-risk cues to the discrete Low / Medium / High classification using conservative thresholds appropriate for an early-warning research classifier.\n"
f"9) Low = comparatively weak overall concern based on supplied information, with no substantial cluster of persistent or high-significance warning indicators.\n"
f"10) Medium = meaningful concern, uncertain or incomplete evidence, one or more important risk factors combined with potentially relevant symptoms, persistent unexplained changes, or a situation reasonably warranting further screening / professional evaluation.\n"
f"11) High = substantial concern produced by multiple strong independent indicators, major risk history plus suspicious progressive changes, highly concerning supplied screening information, or another strong convergence of risk signals warranting prompt professional assessment.\n"
f"12) When evidence sits near a category boundary, examine persistence, progression, severity, independence of signals, quality of evidence, major established risk factors, and missing information before finalizing the category.\n"
f"13) Never allow a single NAZA system metric, entropic value, quantum simulation value, color-sync value, or PUNKD token weight to independently move a patient from Low to High.\n"
f"14) Treat system telemetry as computational context rather than medical evidence.\n"
f"15) If contradictory medical information exists, weight the more specific, objective, persistent, and clinically meaningful information more strongly while increasing uncertainty.\n"
f"16) If the provided information explicitly describes an already confirmed cancer diagnosis, do not pretend to rediscover or independently validate the diagnosis. Classify the risk/concern context conservatively from the supplied information while recognizing internally that diagnosis requires clinical evidence.\n"
f"17) If the information describes emergency or immediately dangerous symptoms, do not downgrade merely because cancer-specific evidence is uncertain; the classifier should conservatively reflect the seriousness of the available pattern while remaining limited to the required Low / Medium / High output.\n"
f"18) PUNKD: detect key medically relevant tokens and locally adjust attention / generation temperature only as part of the existing NAZA decision mechanism. Token frequency alone must not determine the medical classification.\n"
f"19) Triple Check the proposed label against the full input and ensure it does not depend on hallucinated information.\n"
f"20) Do not output internal reasoning, diagnostics, calculations, percentages, medical advice, explanatory text, or chain-of-thought. Return only the single-word classification.\n"
f"[/action]\n\n"
f"[riskdefinitions]\n"
f"Low: comparatively low apparent cancer-related concern from the information supplied. No strong cluster of persistent/progressive warning signs or substantial combined risk evidence is present. This does not exclude cancer and does not override routine age/risk-appropriate screening.\n"
f"Medium: intermediate or uncertain concern. Meaningful risk factors, persistent unexplained symptoms, incomplete but concerning information, relevant history/exposure, or combinations of weaker signals justify increased attention and appropriate professional follow-up or screening consideration.\n"
f"High: substantial concern based on a convergence of strong, persistent, progressive, objectively abnormal, historically significant, or independently reinforcing risk information. This classification indicates need for timely professional evaluation; it is not a cancer diagnosis.\n"
f"[/riskdefinitions]\n\n"
f"[validation]\n"
f"Before final output, internally verify all of the following:\n"
f"- The classification came from supplied patient/contextual evidence rather than invented facts.\n"
f"- Low was not used as equivalent to cancer-free.\n"
f"- High was not used as equivalent to diagnosed cancer.\n"
f"- Missing information was not treated as normal information.\n"
f"- NAZA quantum/entropic/system telemetry was not treated as a medical biomarker.\n"
f"- Persistent and progressive patterns received more attention than isolated vague observations.\n"
f"- Multiple independent warning signals received more weight than repeated descriptions of the same signal.\n"
f"- The selected label is exactly Low, Medium, or High.\n"
f"[/validation]\n\n"
f"[replytemplate]\nLow | Medium | High\n[/replytemplate]"
    )
    return tpl

def header(status:dict):
    s = f" Naza TUI -- Model: {'loaded' if status.get('model_loaded') else 'none'} | Key: {'present' if status.get('key') else 'missing'} | {oqs_status_line()} | {spooky_status_line()} "
    print(color(s.center(80, "-"), fg=35, bold=True))

def model_manager(state:dict):
    while True:
        clear_screen(); header(state)
        lines=[
            "1) Download model from remote repo (httpx)",
            "2) Verify plaintext model hash (compute SHA256)",
            "3) Encrypt plaintext model -> .aes",
            "4) Decrypt .aes -> plaintext (temporary)",
            "5) Delete plaintext model",
            "6) Reinstall/verify pinned liboqs 0.14.0 (hash-checked)",
            "7) Write install script only",
            "8) Back",
            oqs_status_line(),
            spooky_status_line(),
        ]
        print(boxed("Model Manager", lines))
        choice = input("Choose (1-8): ").strip()
        if choice=="1":
            if MODEL_PATH.exists():
                if input("Plaintext model exists; overwrite? (y/N): ").strip().lower()!='y': continue
            try:
                url = MODEL_REPO + MODEL_FILE
                sha, match = download_model_httpx(url, MODEL_PATH, show_progress=True, timeout=None, expected_sha=EXPECTED_HASH)
                print(f"Downloaded to {MODEL_PATH}")
                print(f"Computed SHA256: {sha}")
                if input("Encrypt downloaded model with current key now? (Y/n): ").strip().lower()!='n':
                    encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, state['key'])
                    print(f"Encrypted -> {ENCRYPTED_MODEL}")
                    if input("Remove plaintext model? (Y/n): ").strip().lower()!='n':
                        secure_unlink(MODEL_PATH); print("Plaintext removed.")
            except Exception as e:
                print(f"Download failed: {e}")
            input("Enter to continue...")
        elif choice=="2":
            if not MODEL_PATH.exists(): print("No plaintext model found.")
            else: print(f"SHA256: {sha256_file(MODEL_PATH)}")
            input("Enter to continue...")
        elif choice=="3":
            if not MODEL_PATH.exists(): print("No plaintext model to encrypt."); input("Enter..."); continue
            try:
                sha = verify_model_integrity(MODEL_PATH)
                print(f"Verified model SHA256: {sha}")
            except Exception as e:
                print(color(f"Refusing to encrypt unverified model: {e}", fg=31, bold=True))
                secure_unlink(MODEL_PATH)
                input("Enter...")
                continue
            encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, state['key'])
            if input("Remove plaintext? (Y/n): ").strip().lower()!='n':
                secure_unlink(MODEL_PATH); print("Removed plaintext.")
            input("Enter...")
        elif choice=="4":
            if not ENCRYPTED_MODEL.exists(): print("No .aes model present.")
            else: decrypt_file(ENCRYPTED_MODEL, MODEL_PATH, state['key'])
            input("Enter...")
        elif choice=="5":
            if MODEL_PATH.exists():
                if input(f"Delete {MODEL_PATH}? (y/N): ").strip().lower()=="y": secure_unlink(MODEL_PATH); print("Deleted.")
            else: print("No plaintext model.")
            input("Enter...")
        elif choice=="6":
            path = write_oqs_install_script()
            print(f"Wrote {path} (liboqs {LIBOQS_VER} sha256={LIBOQS_SHA256[:16]}...)")
            if input("Run installer now? needs cmake/make/curl (y/N): ").strip().lower()=="y":
                import subprocess
                rc = subprocess.call(["bash", str(path)])
                print("installer exit", rc)
            input("Enter...")
        elif choice=="7":
            path = write_oqs_install_script()
            print(f"Wrote {path}")
            input("Enter...")
        elif choice=="8": return
        else: print("Invalid.")

async def chat_session(state:dict):
    if not ENCRYPTED_MODEL.exists(): print("No encrypted model found. Please download & encrypt first."); input("Enter..."); return
    decrypt_file(ENCRYPTED_MODEL, SESSION_MODEL_PATH, state['key'])
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=1) as ex:
        try:
            print("Loading model..."); llm = await loop.run_in_executor(ex, load_llama_model_blocking, SESSION_MODEL_PATH)
        except Exception as e:
            print(f"Failed to load: {e}")
            if SESSION_MODEL_PATH.exists():
                secure_unlink(SESSION_MODEL_PATH)
            input("Enter..."); return
        state['model_loaded']=True
        try:
            await init_db(state['key'])
            print("Type /exit to return, /history to show last 10 messages.")
            while True:
                prompt = input("\nYou> ").strip()
                if not prompt: continue
                if prompt in ("/exit","exit","quit"): break
                if prompt=="/history":
                    rows = await fetch_history(state['key'], limit=10)
                    for r in rows: print(f"[{r[0]}] {r[1]}\nQ: {r[2]}\nA: {r[3]}\n{'-'*30}")
                    continue
                def gen(p):
                    out = llm(p, max_tokens=256, temperature=0.7)
                    text = ""
                    if isinstance(out, dict):
                        try: text = out.get("choices",[{"text":""}])[0].get("text","")
                        except Exception: text = out.get("text","")
                    else: text = str(out)
                    text = (text or "").strip()
                    text = text.replace("You are a helpful AI assistant named SmolLM, trained by Hugging Face","").strip()
                    return text
                print("🤖 Thinking...")
                result = await loop.run_in_executor(ex, gen, prompt)
                print("\nModel:\n"+result+"\n")
                await log_interaction(prompt, result, state['key'])
        finally:
            try: del llm
            except Exception: pass
            print("Removing temporary plaintext model...")
            secure_unlink(SESSION_MODEL_PATH)
            state['model_loaded']=False
            input("Enter...")

async def road_scanner_flow(state:dict, mode: str = "ask"):
    if not ENCRYPTED_MODEL.exists(): print("No encrypted model found."); input("Enter..."); return
    if mode == "ask":
        print("1) Road  2) Food/water")
        mode = "food" if (input("Scan type [1]: ").strip() or "1") == "2" else "road"
    data={}
    clear_screen(); header(state)
    if mode == "food":
        print(boxed("Food/Water Scanner", ["Leave blank for defaults"]))
        data['location'] = input("Location (store, site, camp): ").strip() or "unspecified location"
        data['road_type'] = input("Food or water type: ").strip() or "mixed"
        data['weather'] = input("Storage / condition: ").strip() or "unknown"
        data['traffic'] = input("Temperature / handling: ").strip() or "ambient"
        data['obstacles'] = input("Cooked, frozen, or uncooked: ").strip() or "none"
        data['sensor_notes'] = input("Sensor notes: ").strip() or "none"
        data['scan_surface'] = "food_water"
    else:
        print(boxed("Road Scanner", ["Leave blank for defaults"]))
        data['location'] = input("Location / route: ").strip() or "unspecified location"
        data['road_type'] = input("Road type: ").strip() or "highway"
        data['weather'] = input("Weather: ").strip() or "clear"
        data['traffic'] = input("Traffic: ").strip() or "low"
        data['obstacles'] = input("Obstacles: ").strip() or "none"
        data['sensor_notes'] = input("Sensor notes: ").strip() or "none"
        data['scan_surface'] = "road"
    print("\nGeneration options:\n1) Chunked generation + punkd (recommended)\n2) Chunked only\n3) Direct single-call generation")
    gen_choice = input("Choose (1-3) [1]: ").strip() or "1"
    prompt = build_road_scanner_prompt(data, include_system_entropy=True)
    decrypt_file(ENCRYPTED_MODEL, SESSION_MODEL_PATH, state['key'])
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=1) as ex:
        try:
            llm = await loop.run_in_executor(ex, load_llama_model_blocking, SESSION_MODEL_PATH)
        except Exception as e:
            print(f"Model load failed: {e}")
            if SESSION_MODEL_PATH.exists():
                secure_unlink(SESSION_MODEL_PATH)
            input("Enter..."); return
        def gen_direct(p):
            out = llm(p, max_tokens=128, temperature=0.2)
            if isinstance(out, dict):
                try: text = out.get("choices",[{"text":""}])[0].get("text","")
                except Exception: text = out.get("text","")
            else: text = str(out)
            text = (text or "").strip()
            return text.replace("You are a helpful AI assistant named SmolLM, trained by Hugging Face","").strip()
        if gen_choice == "3":
            print("Scanning (single-call)...")
            result = await loop.run_in_executor(ex, gen_direct, prompt)
        else:
            punkd_profile = "balanced" if gen_choice=="1" else "conservative"
            print("Scanning with chunked generation (this may take a moment)...")
            def run_chunked():
                return chunked_generate(llm=llm, prompt=prompt, max_total_tokens=256, chunk_tokens=64, base_temperature=0.18, punkd_profile=punkd_profile, streaming_callback=None)
            result = await loop.run_in_executor(ex, run_chunked)
        text = (result or "").strip().replace("You are a helpful AI assistant named SmolLM, trained by Hugging Face","")
        candidate = text.split()
        label = candidate[0].capitalize() if candidate else ""
        if label not in ("Low","Medium","High"):
            lowered = text.lower()
            if "low" in lowered: label = "Low"
            elif "medium" in lowered: label = "Medium"
            elif "high" in lowered: label = "High"
            else: label = "Medium"
        def show_label(lbl):
            print("\n--- Road Scanner Result ---\n")
            if lbl == "Low": print(color(lbl, fg=32, bold=True))
            elif lbl == "Medium": print(color(lbl, fg=33, bold=True))
            else: print(color(lbl, fg=31, bold=True))

        def relabel(raw):
            t = (raw or "").strip().replace("You are a helpful AI assistant named SmolLM, trained by Hugging Face","")
            cand = t.split()
            lbl = cand[0].capitalize() if cand else ""
            if lbl not in ("Low","Medium","High"):
                low = t.lower()
                if "low" in low: lbl = "Low"
                elif "medium" in low: lbl = "Medium"
                elif "high" in low: lbl = "High"
                else: lbl = "Medium"
            return lbl, t

        show_label(label)
        try:
            rec = persist_scan_receipt(label, prompt, _LAST_SYNC, state["key"])
            print(color(rec, fg=36))
        except Exception:
            rec = ""
        while True:
            print("\nOptions: 1) Re-run with edits [default]  2) Export to JSON  3) Save & return  4) Cancel")
            drain_stdin()
            ch = input("Choose (1-4) [1]: ").strip() or "1"
            if ch == "1":
                print("Re-run: editing fields. Press Enter to keep current value.")
                for k in list(data.keys()):
                    v = input(f"{k} [{data[k]}]: ").strip()
                    if v: data[k] = v
                prompt = build_road_scanner_prompt(data, include_system_entropy=True)
                print("Re-scanning...")
                if gen_choice == "3":
                    result = await loop.run_in_executor(ex, gen_direct, prompt)
                else:
                    def run_chunked2():
                        return chunked_generate(llm=llm, prompt=prompt, max_total_tokens=256, chunk_tokens=64, base_temperature=0.18, punkd_profile=punkd_profile, streaming_callback=None)
                    result = await loop.run_in_executor(ex, run_chunked2)
                label, text = relabel(result)
                show_label(label)
                try:
                    rec = persist_scan_receipt(label, prompt, _LAST_SYNC, state["key"])
                    print(color(rec, fg=36))
                except Exception:
                    rec = ""
                continue
            if ch in ("2", "3"):
                try:
                    await init_db(state['key'])
                    await log_interaction("ROAD_SCANNER_PROMPT:\n"+prompt, "ROAD_SCANNER_RESULT:\n"+label, state['key'])
                except Exception as e:
                    print(f"Failed to log: {e}")
            if ch == "2":
                outp = {"input": data, "prompt": prompt, "result": label, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
                fn = input("Filename to save JSON (default road_scan.json): ").strip() or "road_scan.json"
                _atomic_write_private(Path(fn), json.dumps(outp, indent=2).encode("utf-8")); print(f"Saved {fn}")
            break
        try: del llm
        except Exception: pass
        print("Removing temporary plaintext model...")
        secure_unlink(SESSION_MODEL_PATH)
        drain_stdin()
        input("Enter to return to the main menu...")

async def db_viewer_flow(state:dict):
    if not DB_PATH.exists(): print("No DB found."); input("Enter..."); return
    page=0; per_page=10; search=None
    while True:
        rows = await fetch_history(state['key'], limit=per_page, offset=page*per_page, search=search)
        clear_screen(); header(state)
        title = f"History (page {page+1})"
        print(boxed(title, [f"Search: {search or '(none)'}", "Commands: n=next p=prev s=search q=quit"]))
        if not rows: print("No rows on this page.")
        else:
            for r in rows: print(f"[{r[0]}] {r[1]}\nQ: {r[2]}\nA: {r[3]}\n" + "-"*60)
        cmd = input("cmd (n/p/s/q): ").strip().lower()
        if cmd=="n": page +=1
        elif cmd=="p" and page>0: page -=1
        elif cmd=="s": search = input("Enter search keyword (empty to clear): ").strip() or None; page = 0
        else: break

def _spooky_lab_protector(salt: bytes) -> bytes:

    seed = derive_kek(salt, None)
    return _hkdf_sha512(
        seed + hardware_fingerprint() + RAINBOW_BIND,
        salt,
        b"naza/spooky-combiner-1/lab-protector/v1",
        32,
    )


def _spooky_lab_pack(salt: bytes, payload_hash: bytes, envelope: bytes) -> bytes:
    if len(salt) != 16 or len(payload_hash) != 32:
        raise ValueError("bad SC1 lab metadata")
    return SPOOKY_LAB_MAGIC + bytes([1]) + salt + payload_hash + len(envelope).to_bytes(4, "big") + envelope


def _spooky_lab_unpack(blob: bytes) -> Tuple[bytes, bytes, bytes]:
    if len(blob) < 57 or not blob.startswith(SPOOKY_LAB_MAGIC) or blob[4] != 1:
        raise SpookyCombinerError("SC1 lab artifact authentication failed")
    salt = blob[5:21]
    expected = blob[21:53]
    n = int.from_bytes(blob[53:57], "big")
    if n < 1 or n > 256 * 1024 or len(blob) != 57 + n:
        raise SpookyCombinerError("SC1 lab artifact authentication failed")
    return salt, expected, blob[57:]


def spooky_lab_flow(state: dict):

    while True:
        clear_screen(); header(state)
        st = spooky_status(_OQS)
        lines = [
            "EXPERIMENTAL — invented research construction; not NIST validated.",
            f"Suite: {SPOOKY_SUITE}",
            "Mandatory branches: " + " + ".join(SPOOKY_KEMS),
            spooky_status_line(),
            "1) Run fresh round-trip + tamper self-test",
            "2) Create/replace machine-bound random lab envelope",
            "3) Verify stored lab envelope",
            "4) One-shot create/open benchmark",
            "5) Delete stored lab envelope",
            "6) Back",
        ]
        print(boxed("SpookyCombiner-1 Research Lab", lines, width=80))
        choice = input("Choose (1-6): ").strip()
        if choice == "1":
            if not st.ready:
                print("Unavailable. Install liboqs with ML-KEM-1024 and HQC-256 enabled.")
            else:
                try:
                    t0 = time.perf_counter()
                    result = spooky_self_test(_OQS)
                    dt = time.perf_counter() - t0
                    print(json.dumps(result, indent=2))
                    print(f"Self-test elapsed: {dt:.3f}s")
                except Exception as e:
                    print(f"SC1 self-test failed: {e}")
            input("Enter...")
        elif choice == "2":
            if not st.ready:
                print("Unavailable. Install liboqs with ML-KEM-1024 and HQC-256 enabled.")
                input("Enter..."); continue
            try:
                salt = os.urandom(16)
                protector = _spooky_lab_protector(salt)
                canary = bytearray(os.urandom(64))
                expected = hashlib.sha256(canary).digest()
                envelope = spooky_create_envelope(bytes(canary), protector, _OQS)
                artifact = _spooky_lab_pack(salt, expected, envelope)
                _atomic_write_private(SPOOKY_LAB_PATH, artifact)
                for i in range(len(canary)): canary[i] = 0
                print(f"Wrote {SPOOKY_LAB_PATH} ({len(artifact)} bytes).")
                print("Contains a random canary only — never Naza's live master key.")
            except Exception as e:
                print(f"SC1 create failed: {e}")
            input("Enter...")
        elif choice == "3":
            if not SPOOKY_LAB_PATH.exists():
                print("No stored SC1 lab envelope."); input("Enter..."); continue
            if not st.ready:
                print("Unavailable. Both KEMs must be enabled."); input("Enter..."); continue
            try:
                _assert_private_regular(SPOOKY_LAB_PATH, "SC1 lab artifact")
                salt, expected, envelope = _spooky_lab_unpack(storage.read_private(SPOOKY_LAB_PATH, 1024 * 1024))
                protector = _spooky_lab_protector(salt)
                recovered = bytearray(spooky_open_envelope(envelope, protector, _OQS))
                ok = hmac.compare_digest(hashlib.sha256(recovered).digest(), expected)
                for i in range(len(recovered)): recovered[i] = 0
                if not ok:
                    raise SpookyCombinerError("SC1 lab artifact authentication failed")
                print("SC1 stored-envelope verification: PASS")
            except Exception:
                print("SC1 stored-envelope verification: FAIL (generic authentication failure)")
            input("Enter...")
        elif choice == "4":
            if not st.ready:
                print("Unavailable. Both KEMs must be enabled."); input("Enter..."); continue
            try:
                salt = os.urandom(16)
                protector = _spooky_lab_protector(salt)
                payload = os.urandom(64)
                t0 = time.perf_counter(); envelope = spooky_create_envelope(payload, protector, _OQS); t1 = time.perf_counter()
                recovered = spooky_open_envelope(envelope, protector, _OQS); t2 = time.perf_counter()
                if not hmac.compare_digest(payload, recovered):
                    raise SpookyCombinerError("SC1 benchmark round-trip failed")
                print(f"create={t1-t0:.4f}s open={t2-t1:.4f}s envelope={len(envelope)} bytes")
            except Exception as e:
                print(f"SC1 benchmark failed: {e}")
            input("Enter...")
        elif choice == "5":
            if SPOOKY_LAB_PATH.exists():
                if input(f"Delete {SPOOKY_LAB_PATH}? (y/N): ").strip().lower() == "y":
                    secure_unlink(SPOOKY_LAB_PATH)
                    print("Deleted.")
            else:
                print("No stored SC1 lab envelope.")
            input("Enter...")
        elif choice == "6":
            return
        else:
            print("Invalid.")
            time.sleep(0.5)


def trihybrid_flow(state: dict):
    print("SpookyNaza tri-hybrid: ML-KEM-1024 + HQC-256 + X25519 / AES-256-GCM")
    print("Experimental local key wrapping. Existing model and chat ciphertext stays readable.")
    st = spooky_status(_OQS)
    if not st.ready:
        print("Unavailable: missing " + ", ".join(st.missing))
        input("Enter...")
        return
    pw = read_unlock_token()
    current = storage.read_private(KEY_PATH, 1024 * 1024)
    if current.startswith((b"NKEY2", b"NKEY3", b"NKEY4")) and current[6] & KEY_FLAG_PASSPHRASE and not pw:
        raise ValueError("Current passphrase/token is required to preserve the gate")
    key = load_data_key(pw)
    if not hmac.compare_digest(key, state['key']):
        raise ValueError("Loaded key differs from active session")
    save_wrapped_key(key, pw, mode="tri")
    print("Verified and saved NKEY4 tri-hybrid key envelope.")
    input("Enter...")


def rotation_targets():
    return [ENCRYPTED_MODEL, Path(str(ENCRYPTED_MODEL) + MAC_SUFFIX),
            DB_PATH, Path(str(DB_PATH) + MAC_SUFFIX), KEY_PATH, LOCK_PATH]


def rotate_data_key(old_key: bytes, passphrase: Optional[str]) -> bytes:
    new_key = AESGCM.generate_key(256)
    envelope = build_trihybrid_key(new_key, passphrase)

    def prepare():
        for path in (ENCRYPTED_MODEL, DB_PATH):
            if not path.exists():
                yield None
                yield None
                continue
            _assert_private_regular(path, "encrypted data")
            raw = storage.read_private(path)
            mac = Path(str(path) + MAC_SUFFIX)
            if mac.exists():
                _assert_private_regular(mac, "file MAC")
                expected = hmac.new(_mac_key(old_key), raw, hashlib.sha256).digest()
                if not hmac.compare_digest(storage.read_private(mac, 64), expected):
                    raise ValueError("Existing file MAC check failed")
            plain = aes_decrypt(raw, old_key)
            encrypted = aes_encrypt(plain, new_key)
            if not hmac.compare_digest(aes_decrypt(encrypted, new_key), plain):
                raise ValueError("Staged ciphertext verification failed")
            del plain, raw
            yield encrypted
            yield hmac.new(_mac_key(new_key), encrypted, hashlib.sha256).digest()
        yield envelope
        yield json.dumps({"profile": "spookynaza-nkey4", "suite": tri.SUITE.decode(),
                          "gate": "passphrase" if passphrase else "machine",
                          "experimental": True}, indent=2).encode()

    storage.replace_batch(Path.cwd(), rotation_targets(), prepare)
    return new_key


def rekey_flow(state:dict):
    if not spooky_status(_OQS).ready:
        raise SpookyCombinerError("Default SpookyNaza mode requires ML-KEM-1024 and HQC-256")
    print("Rotate data key and verify all encrypted files")
    choice = input("1) Keep current gate  2) Set new passphrase  3) Cancel\nChoose: ").strip()
    if choice not in ("1", "2"):
        return
    current_pw = read_unlock_token()
    current = storage.read_private(KEY_PATH, 1024 * 1024)
    if current.startswith((b"NKEY2", b"NKEY3", b"NKEY4")) and current[6] & KEY_FLAG_PASSPHRASE and not current_pw:
        raise ValueError("Current passphrase/token is required")
    if not hmac.compare_digest(load_data_key(current_pw), state['key']):
        raise ValueError("On-disk key differs from the active session")
    pw = current_pw
    if choice == "2":
        pw = getpass.getpass("New passphrase: ")
        if not pw or pw != getpass.getpass("Confirm: "):
            raise ValueError("Passphrase is empty or does not match")
        validate_new_passphrase(pw)
    try:
        state['key'] = rotate_data_key(state['key'], pw)
    except BaseException:
        if (Path.cwd() / '.naza-rotation').exists():
            raise SystemExit('Rotation recovery is pending. Restart Naza before accessing encrypted data.')
        raise
    print("Rotation complete: key, ciphertext, and MACs verified and saved.")
    input("Enter...")


def encryption_status_flow(state: dict):
    raw = storage.read_private(KEY_PATH, 1024 * 1024) if KEY_PATH.exists() else b""
    profile = "SpookyNaza tri-hybrid (NKEY4)" if raw.startswith(b"NKEY4") else "Legacy / classical"
    print(boxed("Encryption status", ["Active: " + profile, "New keys: SpookyNaza tri-hybrid",
        oqs_status_line(), "Suite: " + tri.SUITE.decode(),
        "Gate: " + ("passphrase/token" if raw.startswith((b"NKEY2", b"NKEY3", b"NKEY4")) and len(raw) > 6 and raw[6] & KEY_FLAG_PASSPHRASE else "machine-only"),
        "Construction: experimental", "Rotation: verified staging with startup recovery"]))
    input("Enter...")


def safe_cleanup(paths:List[Path]):
    for p in paths:
        try:
            if p.exists(): p.unlink()
        except Exception: pass

def main_menu_loop(state:dict):
    options = ["Model Manager","Chat with model","Road Scanner","Food/Water Scanner","View chat history","SpookyCombiner-1 Research Lab","Enable SpookyNaza tri-hybrid","Encryption status","Rekey / Rotate key","Exit"]
    while True:
        drain_stdin()
        clear_screen(); header(state); print()
        print(boxed("Main Menu", [f"{i+1}) {opt}" for i,opt in enumerate(options)]))
        idx = read_menu_choice(len(options)); choice = options[idx]
        try:
            if choice == "Model Manager": model_manager(state)
            elif choice == "Chat with model": asyncio.run(chat_session(state))
            elif choice == "Road Scanner": asyncio.run(road_scanner_flow(state, "road"))
            elif choice == "Food/Water Scanner": asyncio.run(road_scanner_flow(state, "food"))
            elif choice == "View chat history": asyncio.run(db_viewer_flow(state))
            elif choice == "SpookyCombiner-1 Research Lab": spooky_lab_flow(state)
            elif choice == "Enable SpookyNaza tri-hybrid": trihybrid_flow(state)
            elif choice == "Encryption status": encryption_status_flow(state)
            elif choice == "Rekey / Rotate key": rekey_flow(state)
            elif choice == "Exit": print("Goodbye."); return
        except KeyboardInterrupt:
            print("\nBack to menu.")
        except Exception as e:
            print(f"That step stopped ({e}). Back to menu.")
            input("Enter to continue...")
        drain_stdin()

def scanner_ready() -> bool:
    return bool(KEY_PATH.exists() and ENCRYPTED_MODEL.exists() and ENCRYPTED_MODEL.stat().st_size > 0)

def main():
    cleanup_private_temps()
    if storage.recover(Path.cwd(), rotation_targets()):
        print("Recovered interrupted rotation; restored the previous encrypted files and key.")
    for bad in ("LD_PRELOAD", "LD_LIBRARY_PATH"):
        if os.environ.get(bad) and "liboqs" not in os.environ.get(bad, ""):
            print("Note: {} is set. A loader hook can see keys in RAM.".format(bad))
    try:
        key = ensure_key_interactive()
    except Exception as exc:
        raise SystemExit("Key initialization or unlock failed; refusing to create an ungated replacement.") from exc
    state = {"key": key, "model_loaded": False}
    try:
        asyncio.run(init_db(state['key']))
    except Exception as exc:
        raise SystemExit("Encrypted history authentication failed; refusing to continue.") from exc
    try:
        if scanner_ready():
            print("Model and key found. Opening Road Scanner...")
            try:
                asyncio.run(road_scanner_flow(state))
            except KeyboardInterrupt:
                print("\nBack to menu.")
            except Exception as e:
                print(f"Scanner stopped ({e}). Opening menu.")
                input("Enter to continue...")
        else:
            print("Model or key not ready. Open Model Manager (option 1) to download.")
        main_menu_loop(state)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        show_cursor()

if __name__=="__main__":
    main()
