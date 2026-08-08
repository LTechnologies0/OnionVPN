#!/usr/bin/env bash
# CI / local: every jniLibs .so must only NEEDED Bionic (+ liblog).
# Allowlist: libc, libm, libdl, liblog.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${1:-$ROOT/app/src/main/jniLibs}"
ALLOW='^(libc|libm|libdl|liblog)\.so$'
READELF="$(command -v llvm-readelf || command -v readelf || true)"

if [[ -z "$READELF" ]]; then
  echo "ERROR: readelf/llvm-readelf required" >&2
  exit 1
fi
if [[ ! -d "$DIR" ]]; then
  echo "ERROR: missing $DIR" >&2
  exit 1
fi

fail=0
count=0
while IFS= read -r -d '' so; do
  count=$((count + 1))
  mapfile -t needed < <("$READELF" -d "$so" 2>/dev/null | grep NEEDED | sed -n 's/.*\[\(.*\)\].*/\1/p')
  bad=()
  for lib in "${needed[@]}"; do
    [[ -z "$lib" ]] && continue
    if ! [[ "$lib" =~ $ALLOW ]]; then
      bad+=("$lib")
    fi
  done
  rel="${so#"$ROOT/"}"
  if [[ ${#bad[@]} -gt 0 ]]; then
    echo "FAIL $rel — non-standalone NEEDED: ${bad[*]}" >&2
    fail=1
  else
    echo "OK $rel (${needed[*]})"
  fi
done < <(find "$DIR" -type f -name '*.so' -print0 | sort -z)

if [[ "$count" -eq 0 ]]; then
  echo "ERROR: no .so under $DIR" >&2
  exit 1
fi
exit "$fail"
