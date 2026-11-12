#!/usr/bin/env bash
# Build libhev_fromstr_jni.so for OnionVPN jniLibs (arm64-v8a + x86_64).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$(cd "$(dirname "$0")" && pwd)/hev_fromstr_jni.c"
ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
NDK="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/27.3.13750724}"
PREBUILT="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
API=26

build_one() {
  local triple="$1" abi="$2"
  local cc="$PREBUILT/${triple}${API}-clang"
  local out="$ROOT/app/src/main/jniLibs/$abi/libhev_fromstr_jni.so"
  mkdir -p "$(dirname "$out")"
  "$cc" -shared -fPIC -O2 -Wl,-soname,libhev_fromstr_jni.so \
    -o "$out" "$SRC" -ldl -llog -pthread
  echo "Built $out"
}

build_one aarch64-linux-android arm64-v8a
build_one x86_64-linux-android x86_64
echo "hev_fromstr_jni OK"
