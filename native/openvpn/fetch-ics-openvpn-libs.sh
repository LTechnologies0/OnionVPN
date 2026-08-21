#!/usr/bin/env bash
# Fetch TARGET_ANDROID OpenVPN binaries from F-Droid "OpenVPN for Android" (de.blinkt.openvpn).
# GPL-2.0 — shipping these .so files obligates GPL compliance (see SECURITY.md / NOTICE).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION_CODE="${1:-219}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

APK_URL="https://f-droid.org/repo/de.blinkt.openvpn_${VERSION_CODE}.apk"
echo "Downloading $APK_URL"
curl -fL --retry 3 -o "$TMP/openvpn.apk" "$APK_URL"
unzip -qo "$TMP/openvpn.apk" -d "$TMP/apk" \
  'lib/arm64-v8a/libovpnexec.so' 'lib/arm64-v8a/libopenvpn.so' \
  'lib/x86_64/libovpnexec.so' 'lib/x86_64/libopenvpn.so' \
  'assets/pie_openvpn.arm64-v8a' 'assets/pie_openvpn.x86_64'

for abi in arm64-v8a x86_64; do
  dest="$ROOT/app/src/main/jniLibs/$abi"
  mkdir -p "$dest"
  cp -f "$TMP/apk/lib/$abi/libovpnexec.so" "$dest/"
  cp -f "$TMP/apk/lib/$abi/libopenvpn.so" "$dest/"
  chmod +x "$dest/libovpnexec.so"
  echo "Installed $dest/libovpnexec.so + libopenvpn.so"
done

mkdir -p "$ROOT/app/src/main/assets/openvpn"
cp -f "$TMP/apk/assets/pie_openvpn.arm64-v8a" "$ROOT/app/src/main/assets/openvpn/"
cp -f "$TMP/apk/assets/pie_openvpn.x86_64" "$ROOT/app/src/main/assets/openvpn/"
echo "Done. F-Droid de.blinkt.openvpn_${VERSION_CODE} → jniLibs + assets/openvpn"
