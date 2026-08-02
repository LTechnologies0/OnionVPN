#!/usr/bin/env bash
# Build libonionmasq_mobile.so and copy into OnionVPN jniLibs.
# Requires: Rust ≥1.91, cargo-ndk, Android NDK 27.3.13750724 (or set SKIP_NDK_VERSION_CHECK=1).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OM_SRC="${ONIONMASQ_SRC:-$ROOT/third_party/onionmasq}"
if [[ ! -d "$OM_SRC/crates/onionmasq-mobile" ]]; then
  echo "onionmasq sources missing at $OM_SRC (clone tpo/core/onionmasq)" >&2
  exit 1
fi

export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/27.3.13750724}"
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
export ANDROID_NDK="$ANDROID_NDK_HOME"

ARCHS="${1:-arm64-v8a}"
cd "$OM_SRC"

if [[ "${SKIP_NDK_VERSION_CHECK:-}" == "1" ]]; then
  # Temporarily relax build-ndk.sh version gate for local NDK variants.
  sed -i.bak 's/EXPECTED_NDK_VERSION=.*/EXPECTED_NDK_VERSION="$(basename "$ANDROID_NDK_ROOT")"/' build-ndk.sh
fi

./build-ndk.sh $ARCHS

# cargo-ndk / build-ndk typically places .so under android/.../jniLibs or target/
for arch in $ARCHS; do
  found="$(find "$OM_SRC" -path "*/$arch/libonionmasq_mobile.so" 2>/dev/null | head -1 || true)"
  if [[ -z "$found" ]]; then
    found="$(find "$OM_SRC/target" -name 'libonionmasq_mobile.so' 2>/dev/null | head -1 || true)"
  fi
  if [[ -z "$found" ]]; then
    echo "libonionmasq_mobile.so not found for $arch" >&2
    exit 1
  fi
  dest="$ROOT/app/src/main/jniLibs/$arch"
  mkdir -p "$dest"
  cp -f "$found" "$dest/libonionmasq_mobile.so"
  echo "Installed $dest/libonionmasq_mobile.so from $found"
done
