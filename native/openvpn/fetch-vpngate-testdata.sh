#!/usr/bin/env bash
# Refresh VPN Gate TCP .ovpn samples (academic free relays — not for private traffic).
# API: https://www.vpngate.net/api/iphone/
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/testdata"
mkdir -p "$OUT"
CSV="$(mktemp)"
trap 'rm -f "$CSV"' EXIT
curl -fsSL "https://www.vpngate.net/api/iphone/" -o "$CSV"
python3 - "$CSV" "$OUT" <<'PY'
import csv, base64, re, sys
from pathlib import Path
csv_path, out_dir = sys.argv[1], Path(sys.argv[2])
text = open(csv_path, encoding="utf-8", errors="replace").read().splitlines()
lines = [l for l in text if l and not l.startswith("*")]
rows = []
for row in csv.DictReader(lines):
    b64 = row.get("OpenVPN_ConfigData_Base64") or ""
    if not b64:
        continue
    try:
        cfg = base64.b64decode(b64).decode("utf-8", "replace")
    except Exception:
        continue
    if not re.search(r"proto\s+tcp", cfg, re.I):
        continue
    score = int(row.get("Score") or 0)
    rows.append((score, row.get("CountryShort") or "XX", row.get("IP") or "0.0.0.0", cfg))
rows.sort(key=lambda x: -x[0])
# Drop stale samples then write top 3
for p in out_dir.glob("vpngate-tcp-*.ovpn"):
    p.unlink()
for score, cc, ip, cfg in rows[:3]:
    path = out_dir / f"vpngate-tcp-{cc}-{ip}.ovpn"
    path.write_text(cfg)
    print(f"wrote {path.name} score={score}")
print(f"tcp candidates={len(rows)} (auth often vpn/vpn if prompted)")
PY
