#!/usr/bin/env bash
# Fetches Tor, DNSCrypt, hev-socks5-tunnel, and Tor pluggable transports into jniLibs.
# Supported ABIs (matching release splits): arm64-v8a, x86_64
#
# Tor (C / little-t, default engine) + PTs:
#   LTechnologies0/Tor-Android-build-script GitHub Releases
#   https://github.com/LTechnologies0/Tor-Android-build-script
#   PTs built with -Wl,-z,max-page-size=16384 (Android 16 KB pages)
# Arti (Rust, optional engine): org.torproject:arti-mobile Maven AAR (Gradle), not this script
# DNSCrypt + hev: InviZible Lite / sockstun APKs
# Bridge presets JSON: Tor Browser Android pt_config.json (builtin lines only)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/onionvpn-bin-fetch"
mkdir -p "$TMP"

INVIZIBLE_X86_URL="https://github.com/Gedsh/InviZible/releases/download/v7.5.0-stable/Invizible_Lite_ver.7.5.0_x86_64.apk"
INVIZIBLE_ARM64_URL="https://github.com/Gedsh/InviZible/releases/download/v7.5.0-stable/Invizible_Lite_ver.7.5.0_arm64.apk"
SOCKSTUN_URL="https://github.com/heiher/sockstun/releases/download/7.0/hev.sockstun-7.0-release.apk"

TOR_RELEASE_BASE="https://github.com/LTechnologies0/Tor-Android-build-script/releases/latest/download"
TOR_ARM64_URL="${TOR_RELEASE_BASE}/libtor-arm64-v8a.so"
TOR_X86_64_URL="${TOR_RELEASE_BASE}/libtor-x86_64.so"
PT_ARM64_LYREBIRD_URL="${TOR_RELEASE_BASE}/libLyrebird-arm64-v8a.so"
PT_ARM64_CONJURE_URL="${TOR_RELEASE_BASE}/libConjure-arm64-v8a.so"
PT_X86_LYREBIRD_URL="${TOR_RELEASE_BASE}/libLyrebird-x86_64.so"
PT_X86_CONJURE_URL="${TOR_RELEASE_BASE}/libConjure-x86_64.so"

# Builtin bridge *lines* (not binaries) from Tor Browser Android.
TBA_VERSION="${TBA_VERSION:-15.0}"
TBA_ARM64_URL="https://archive.torproject.org/tor-package-archive/torbrowser/${TBA_VERSION}/tor-browser-android-aarch64-${TBA_VERSION}.apk"

fetch() {
  local url="$1" dest="$2"
  if [[ -f "$dest" ]]; then return 0; fi
  echo "Downloading $(basename "$dest")..."
  curl -fsSL -L -o "$dest" "$url"
}

fetch_force() {
  local url="$1" dest="$2"
  echo "Downloading $(basename "$dest")..."
  curl -fsSL -L -o "$dest" "$url"
}

fetch_optional() {
  local url="$1" dest="$2"
  echo "Downloading $(basename "$dest") (optional)..."
  if curl -fsSL -L -o "$dest" "$url"; then
    return 0
  fi
  rm -f "$dest"
  echo "  skip $(basename "$dest") — not on release yet"
  return 1
}

fetch "$INVIZIBLE_X86_URL" "$TMP/invizible_x86.apk"
fetch "$INVIZIBLE_ARM64_URL" "$TMP/invizible_arm64.apk"
fetch "$SOCKSTUN_URL" "$TMP/sockstun.apk"
fetch "$TBA_ARM64_URL" "$TMP/tba_arm64.apk"
fetch_force "$TOR_ARM64_URL" "$TMP/libtor-arm64.so"
fetch_force "$TOR_X86_64_URL" "$TMP/libtor-x86_64.so"
fetch_force "$PT_ARM64_LYREBIRD_URL" "$TMP/libLyrebird-arm64.so" || \
  echo "WARN: libLyrebird-arm64 missing from Tor-Android-build-script release"
fetch_optional "$PT_ARM64_CONJURE_URL" "$TMP/libConjure-arm64.so" || true
fetch_optional "$PT_X86_LYREBIRD_URL" "$TMP/libLyrebird-x86_64.so" || true
fetch_optional "$PT_X86_CONJURE_URL" "$TMP/libConjure-x86_64.so" || true

install_abi() {
  local invizible_apk="$1" jni_abi="$2" tor_so="$3" lyrebird_so="$4" conjure_so="$5"
  local lib_dir="$ROOT/app/src/main/jniLibs/$jni_abi"
  mkdir -p "$lib_dir"
  cp -f "$tor_so" "$lib_dir/libtor.so"
  unzip -p "$invizible_apk" "lib/$jni_abi/libdnscrypt-proxy.so" >"$lib_dir/libdnscrypt-proxy.so"
  unzip -p "$TMP/sockstun.apk" "lib/$jni_abi/libhev-socks5-tunnel.so" >"$lib_dir/libhev-socks5-tunnel.so"

  rm -f "$lib_dir"/libobfs4proxy.so "$lib_dir"/libsnowflake.so \
        "$lib_dir"/libLyrebird.so "$lib_dir"/libConjure.so
  if [[ -f "$lyrebird_so" ]]; then
    cp -f "$lyrebird_so" "$lib_dir/libLyrebird.so"
  else
    echo "ERROR: missing Lyrebird for $jni_abi" >&2
    exit 1
  fi
  if [[ -n "$conjure_so" && -f "$conjure_so" ]]; then
    cp -f "$conjure_so" "$lib_dir/libConjure.so"
  fi

  chmod +x "$lib_dir"/*.so
  local conjure_sz=0
  [[ -f "$lib_dir/libConjure.so" ]] && conjure_sz=$(wc -c <"$lib_dir/libConjure.so")
  echo "OK $jni_abi tor=$(wc -c <"$lib_dir/libtor.so") lyrebird=$(wc -c <"$lib_dir/libLyrebird.so") conjure=$conjure_sz"
}

install_abi "$TMP/invizible_arm64.apk" "arm64-v8a" "$TMP/libtor-arm64.so" \
  "$TMP/libLyrebird-arm64.so" "$TMP/libConjure-arm64.so"
install_abi "$TMP/invizible_x86.apk" "x86_64" "$TMP/libtor-x86_64.so" \
  "${TMP}/libLyrebird-x86_64.so" "${TMP}/libConjure-x86_64.so"

# Builtin bridge lines from TBA pt_config.json
python3 - "$ROOT" "$TMP/tba_arm64.apk" "$TBA_VERSION" <<'PY'
import json, zipfile, pathlib, sys
root = pathlib.Path(sys.argv[1])
tba = sys.argv[2]
ver = sys.argv[3]
with zipfile.ZipFile(tba) as z:
    cfg = json.loads(z.read("assets/common/pt_config.json"))
out = {
    "source": f"Tor Browser Android {ver} pt_config.json (bridge lines; PTs from LTechnologies0 build)",
    "bridges": {},
}
bridges = cfg["bridges"]
for key in ("obfs4", "snowflake", "meek", "meek-azure"):
    if key in bridges:
        out["bridges"]["meek" if key == "meek-azure" else key] = bridges[key]
path = root / "app/src/main/assets/pt_bridges.json"
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(out, indent=2) + "\n")
print("Wrote", path)
PY

echo "Native binaries installed under app/src/main/jniLibs/"
echo "Tor+PTs: LTechnologies0/Tor-Android-build-script | presets: TBA ${TBA_VERSION}"
