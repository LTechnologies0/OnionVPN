#!/usr/bin/env bash
# Verify OnionVPN APK/manifest opts into ARM MTE (android:memtagMode=async)
# and that no library merge cleared or set memtagMode to off/none.
#
# Usage:
#   ./scripts/verify-memtag-manifest.sh [path-to.apk|path-to-AndroidManifest.xml]
# Default: latest merged debug/release manifest under app/build/, else debug APK.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
  for candidate in \
    "$ROOT/app/build/intermediates/merged_manifest/debug/processDebugMainManifest/AndroidManifest.xml" \
    "$ROOT/app/build/intermediates/merged_manifest/release/processReleaseMainManifest/AndroidManifest.xml" \
    "$ROOT/app/build/intermediates/merged_manifests/debug/processDebugManifest/AndroidManifest.xml" \
    "$ROOT/app/build/outputs/apk/debug/app-debug.apk"
  do
    if [[ -f "$candidate" ]]; then
      TARGET="$candidate"
      break
    fi
  done
fi

if [[ -z "${TARGET:-}" || ! -f "$TARGET" ]]; then
  echo "No manifest/APK found. Build first: ./gradlew :app:processDebugMainManifest" >&2
  exit 1
fi

extract_manifest() {
  local src="$1"
  if [[ "$src" == *.apk ]]; then
    if command -v aapt2 >/dev/null 2>&1; then
      aapt2 dump xmltree --file AndroidManifest.xml "$src" 2>/dev/null || aapt dump xmltree "$src" AndroidManifest.xml
    elif command -v aapt >/dev/null 2>&1; then
      aapt dump xmltree "$src" AndroidManifest.xml
    else
      echo "Need aapt/aapt2 to dump APK manifest" >&2
      exit 1
    fi
  else
    cat "$src"
  fi
}

DUMP="$(extract_manifest "$TARGET")"

# Fail closed: dependency merges must not disable MTE.
if echo "$DUMP" | grep -Eiq 'memtagMode[^>]*(="?(off|none)"?|>(off|none)<)|android:memtagMode="(off|none)"'; then
  echo "$DUMP" | grep -Ei 'memtagMode' | head -20 || true
  echo "FAIL: memtagMode is off/none in $TARGET (dependency cleared app MTE)" >&2
  exit 1
fi

if echo "$DUMP" | grep -Eq 'memtagMode[^>]*(async|="async"|0x[0-9a-f]+.*async)|android:memtagMode="async"'; then
  echo "OK: memtagMode=async present in $TARGET"
  exit 0
fi

# aapt binary XML sometimes prints enum MEMTAG_ASYNC (value 1 or similar).
if echo "$DUMP" | grep -Eq 'MEMTAG_ASYNC|memtagMode.*=.*0x1[^0-9a-f]'; then
  echo "OK: MEMTAG_ASYNC / memtagMode async enum in $TARGET"
  exit 0
fi

if echo "$DUMP" | grep -Eq 'memtagMode|MEMTAG'; then
  echo "$DUMP" | grep -E 'memtagMode|MEMTAG' | head -20
  echo "FAIL: memtag-related attrs found but async not confirmed in $TARGET" >&2
  exit 1
fi

echo "FAIL: android:memtagMode=async not found in $TARGET" >&2
exit 1
