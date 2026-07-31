#!/usr/bin/env bash
# Build OnionVPN-patched libarti_mobile_ex.so and install into app jniLibs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMMON="${ROOT}/third_party/arti-mobile-ex/common"
OUT_BASE="${ROOT}/app/src/main/jniLibs"

export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}/ndk/27.2.12479018}"
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

rustup target add aarch64-linux-android x86_64-linux-android

cd "${COMMON}"
echo "Building arti_mobile_ex (OnionVPN control API) with NDK=${ANDROID_NDK_HOME}"
RUSTFLAGS='-C link-arg=-s' cargo ndk \
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

echo "Done. Patched libarti_mobile_ex.so installed under app/src/main/jniLibs/"
