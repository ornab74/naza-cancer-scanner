# NAZA — recovered native Android / Termux build

This repository is the cleaned replacement tree reconstructed from the supplied
NAZA recovery snapshot dated **2026-09-14**. The recovered application is kept
as a Python/Termux program; this repository does **not** contain the abandoned
pure-Zig rewrite attempt.

The canonical Android path is now **native Termux**:

```text
naza-termux-boot.sh
        ↓
naza_unlock.sh
        ↓
Android Keystore Gate 3
        ↓
run_naza.sh
        ↓
naza_crypto_preflight.py
        ↓
main.py
```

There is no normal proot hop in this path.

## Install on Android

From an extracted release ZIP or a Git clone inside Termux:

```bash
chmod +x install.sh
./install.sh
```

The installer copies the repository to `$HOME/naza` when necessary and runs the
native reconciliation installer. Existing models, encrypted history, `.enc_key`,
and private runtime state are intentionally preserved.

After installation:

```bash
cd ~/naza
./naza-termux-boot.sh
```

For a plain launcher after a fresh Gate-3 authorization token already exists:

```bash
./run_naza.sh
```

See [`ANDROID_INSTALL.md`](ANDROID_INSTALL.md) and
[`TERMUX_UNLOCK.md`](TERMUX_UNLOCK.md).

## Recovered application core

The repository keeps the supplied recovery implementation, including:

- `main.py` — unified NAZA TUI, model handling, encrypted history, scanners
- `spooky_combiner.py` — ML-KEM + HQC combiner
- `spooky_trihybrid.py` — ML-KEM + HQC + X25519 NKEY4 envelope
- `naza_storage.py` — hardened atomic storage/rotation helpers
- `naza_crypto_preflight.py` — startup cryptographic/runtime checks
- `tests/` — recovered security and regression tests

Recovery provenance and core hashes are recorded in
[`RECOVERY_PROVENANCE.md`](RECOVERY_PROVENANCE.md).

## Exact GGUF model pin

The recovered `main.py` selects:

```text
llama3-small-Q3_K_M.gguf
```

from:

```text
https://huggingface.co/tensorblock/llama3-small-GGUF/resolve/main/
```

with SHA-256:

```text
8e4f4856fb84bafb895f1eb08e6c03e4be613ead2d942f91561aeac742a619aa
```

Model verification is fail-closed before promotion/loading. The GGUF itself is
runtime data and is deliberately excluded from Git/release archives.

## Cryptographic profile

New recovered envelopes default to the experimental tri-hybrid profile:

```text
NKEY4
ML-KEM-1024 + HQC-256 + X25519
HKDF-SHA512
AES-256-GCM
```

New NKEY4 v2 envelopes use independent Argon2id lanes for the gate material and
device fingerprint, then combine them with domain-separated HKDF-SHA512. The
machine-only Android mode derives both separated lanes from hardware identity;
passphrase and Android Keystore modes add their gate secret to the first lane.
Existing NKEY4 v1 envelopes remain readable for migration.

The native installer builds/verifies the pinned liboqs backend and checks that
`ML-KEM-1024` and `HQC-256` are available before declaring the installation
healthy.

The cryptographic construction is experimental software. Do not treat its
existence as a substitute for independent review of the protocol or
implementation.

## Gate 3

Gate 3 uses an Android Keystore RSA-2048 key named `naza-unlock`. The installer
requires the key to be hardware-backed and Android-user-authentication gated.

The unlock helper creates a random 32-byte challenge once and stores it in
`$HOME/.naza/challenge` with owner-only permissions. The challenge is retained:
with deterministic RSA PKCS#1 v1.5 signing this yields a repeatable derived
64-hex gate secret, which is required for reopening data already wrapped with
that gate. The Keystore private key itself never leaves Android Keystore.

Do **not** delete `$HOME/.naza/challenge` after you have used Gate 3 to wrap a
key unless you have first rewrapped/rotated that data key to another gate.

## Native installer stack

The recovered reconciliation installer handles the Android stack, including:

- Termux build/runtime packages
- `venv-termux`
- liboqs 0.14.0
- liboqs-python 0.12.0
- ML-KEM-1024 / HQC-256 verification
- llama-cpp-python 0.3.1 plus recovered Android loader patch
- cryptography 46.0.7
- X25519 / AES-256-GCM verification
- Android Keystore Gate 3 setup
- Python and shell syntax validation
- cryptographic startup preflight

The exact recovered pins are retained in the installer and requirement files.

## Verification

Before committing or releasing:

```bash
./tools/verify-tree.sh
```

The recovered test suite currently contains 50 tests. The real-liboqs test is
skipped on hosts where liboqs is not installed; the installer performs real
liboqs verification on Android.

## Build a clean release ZIP

```bash
./tools/make-release.sh naza-android-recovered-v3
```

The release builder excludes models, venvs, caches, logs, local secrets and
runtime state, regenerates `SHA256SUMS` inside the payload, normalizes archive
timestamps, and prints the final ZIP SHA-256.

## Replace the existing GitHub repository

This archive is intended to replace the old working tree rather than merge all
of its stale files. Follow [`REPLACE_REPO.md`](REPLACE_REPO.md) to preserve only
`.git`, copy this recovered tree over it, stage deletions with `git add -A`, and
commit the replacement as one reviewable change.

## Repository layout

```text
install.sh                         clean native-Termux entry point
install-native-termux-repair.sh   recovered reconciliation installer
install_liboqs_0.14.0.sh          pinned liboqs builder
naza-termux-boot.sh               Gate-3 boot menu
naza_unlock.sh                    Android Keystore authorization helper
run_naza.sh                       hardened runtime + preflight launcher
main.py                           recovered NAZA application
spooky_combiner.py                dual-PQ combiner
spooky_trihybrid.py               NKEY4 tri-hybrid wrapper
naza_storage.py                   hardened storage helpers
naza_crypto_preflight.py          runtime crypto checks
tests/                            recovered regression/security suite
tools/                            verify/release helpers
```

## Risk-scanner warning

NAZA's road and food/water scanner output is experimental decision-support
software. A `Low`, `Medium`, or `High` label is not proof that a road, vehicle,
food item, water source, device, or environment is safe or unsafe. Use direct
observation, trusted measurements/tests, advisories, and professional/emergency
guidance where appropriate.
