#!/usr/bin/env bash
# Fetches Tor, DNSCrypt, and hev-socks5-tunnel .so into app/src/main/jniLibs.
# Supported ABIs (matching release splits): arm64-v8a, x86_64
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/onionvpn-bin-fetch"
mkdir -p "$TMP"

INVIZIBLE_X86_URL="https://github.com/Gedsh/InviZible/releases/download/v7.4.0-stable/Invizible_Lite_ver.7.4.0_x86_64.apk"
INVIZIBLE_ARM64_URL="https://github.com/Gedsh/InviZible/releases/download/v7.4.0-stable/Invizible_Lite_ver.7.4.0_arm64.apk"
SOCKSTUN_URL="https://github.com/heiher/sockstun/releases/download/7.0/hev.sockstun-7.0-release.apk"

fetch() {
  local url="$1" dest="$2"
  if [[ -f "$dest" ]]; then return 0; fi
  echo "Downloading $(basename "$dest")..."
  curl -fsSL -L -o "$dest" "$url"
}

fetch "$INVIZIBLE_X86_URL" "$TMP/invizible_x86.apk"
fetch "$INVIZIBLE_ARM64_URL" "$TMP/invizible_arm64.apk"
fetch "$SOCKSTUN_URL" "$TMP/sockstun.apk"

install_abi() {
  local invizible_apk="$1" jni_abi="$2"
  local lib_dir="$ROOT/app/src/main/jniLibs/$jni_abi"
  mkdir -p "$lib_dir"
  unzip -p "$invizible_apk" "lib/$jni_abi/libtor.so" >"$lib_dir/libtor.so"
  unzip -p "$invizible_apk" "lib/$jni_abi/libdnscrypt-proxy.so" >"$lib_dir/libdnscrypt-proxy.so"
  unzip -p "$TMP/sockstun.apk" "lib/$jni_abi/libhev-socks5-tunnel.so" >"$lib_dir/libhev-socks5-tunnel.so"
  chmod +x "$lib_dir"/*.so
  echo "OK $jni_abi"
}

install_abi "$TMP/invizible_arm64.apk" "arm64-v8a"
install_abi "$TMP/invizible_x86.apk" "x86_64"
echo "Native binaries installed under app/src/main/jniLibs/"
