#!/usr/bin/env bash
# Build OnionVPN-patched libarti_mobile_ex.so and install into app jniLibs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMMON="${ROOT}/third_party/arti-mobile-ex/common"
OUT_BASE="${ROOT}/app/src/main/jniLibs"

export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}/ndk/28.0.13004108}"
if [[ ! -d "${ANDROID_NDK_HOME}" ]]; then
  # Prefer newest installed NDK under SDK.
  ANDROID_NDK_HOME="$(ls -d "${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}/ndk"/* 2>/dev/null | sort -V | tail -1 || true)"
fi
export NDK_HOME="${ANDROID_NDK_HOME}"

if [[ ! -d "${ANDROID_NDK_HOME}" ]]; then
  echo "ANDROID_NDK_HOME missing: ${ANDROID_NDK_HOME}" >&2
  exit 1
fi

# NDK clang major may differ from what rustc expects (17).
CLANG_ROOT="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/lib/clang"
if [[ -d "${CLANG_ROOT}" && ! -e "${CLANG_ROOT}/17" ]]; then
  actual="$(basename "$(ls -d "${CLANG_ROOT}"/* | head -1)")"
  ln -sfn "${actual}" "${CLANG_ROOT}/17"
fi

if ! command -v cargo-ndk >/dev/null 2>&1; then
  cargo install cargo-ndk --version 3.5.4
fi

if command -v rustup >/dev/null 2>&1; then
  rustup target add aarch64-linux-android x86_64-linux-android
else
  echo "rustup not found — assuming Android Rust targets already installed"
fi

cd "${COMMON}"
echo "Building arti_mobile_ex (OnionVPN control API) with NDK=${ANDROID_NDK_HOME}"
# Android 15+ 16 KB page devices reject LOAD align < 16384 (see developer.android.com/16kb-page-size).
export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-s"
cargo ndk \
  -t arm64-v8a \
  -t x86_64 \
  -o "${OUT_BASE}" \
  build --release

# cargo-ndk names from [lib] name = arti_mobile_ex → libarti_mobile_ex.so
for abi in arm64-v8a x86_64; do
  so="${OUT_BASE}/${abi}/libarti_mobile_ex.so"
  if [[ ! -f "${so}" ]]; then
    echo "Missing ${so}" >&2
    exit 1
  fi
  echo "OK ${so} ($(stat -c%s "${so}") bytes)"
  nm -D "${so}" | grep -E 'ArtiControlNative|startArtiProxyJNI' || true
done

# Verify 16 KB ELF LOAD alignment (fail the build if still 4 KB).
OUT_BASE="${OUT_BASE}" python3 - <<'PY'
import os, struct, sys

def max_load_align(path: str) -> int:
    with open(path, "rb") as f:
        hdr = f.read(64)
    if hdr[:4] != b"\x7fELF":
        raise SystemExit(f"not ELF: {path}")
    ei_class = hdr[4]
    if ei_class != 2:
        raise SystemExit(f"expected ELF64: {path}")
    e_phoff = struct.unpack_from("<Q", hdr, 32)[0]
    e_phentsize = struct.unpack_from("<H", hdr, 54)[0]
    e_phnum = struct.unpack_from("<H", hdr, 56)[0]
    with open(path, "rb") as f:
        f.seek(e_phoff)
        ph = f.read(e_phentsize * e_phnum)
    max_align = 0
    for i in range(e_phnum):
        off = i * e_phentsize
        p_type, _, _, _, _, _, _, p_align = struct.unpack_from("<IIQQQQQQ", ph, off)
        if p_type == 1:  # PT_LOAD
            max_align = max(max_align, p_align)
    return max_align

out = os.environ["OUT_BASE"]
failed = False
for abi in ("arm64-v8a", "x86_64"):
    so = f"{out}/{abi}/libarti_mobile_ex.so"
    align = max_load_align(so)
    status = "OK" if align >= 16384 else "BAD"
    print(f"{status} align={align} {so}")
    if align < 16384:
        failed = True
if failed:
    raise SystemExit("libarti_mobile_ex.so is not 16KB-page aligned")
PY

echo "Done. Patched libarti_mobile_ex.so installed under app/src/main/jniLibs/"
