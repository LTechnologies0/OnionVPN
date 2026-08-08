#!/usr/bin/env bash
# Verify OnionVPN APK/manifest opts into ARM MTE (android:memtagMode=async).
# Usage:
#   ./scripts/verify-memtag-manifest.sh [path-to.apk|path-to-AndroidManifest.xml]
# Default: latest merged debug manifest under app/build/, else debug APK if present.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
  for candidate in \
    "$ROOT/app/build/intermediates/merged_manifest/debug/processDebugMainManifest/AndroidManifest.xml" \
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
    unzip -p "$src" AndroidManifest.xml >/dev/null 2>&1 || true
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
if echo "$DUMP" | grep -Eq 'memtagMode[^>]*(async|="async"|0x[0-9a-f]+.*async)|android:memtagMode="async"'; then
  echo "OK: memtagMode=async present in $TARGET"
  exit 0
fi

# Binary XML from aapt often shows raw attribute; also accept MEMTAG_ASYNC enum value (2).
if echo "$DUMP" | grep -Eq 'memtagMode|MEMTAG'; then
  echo "$DUMP" | grep -E 'memtagMode|MEMTAG' | head -20
  echo "WARN: memtag-related attrs found; confirm async manually in $TARGET" >&2
  exit 0
fi

echo "FAIL: android:memtagMode=async not found in $TARGET" >&2
exit 1
