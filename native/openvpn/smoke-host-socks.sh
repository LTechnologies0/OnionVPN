#!/usr/bin/env bash
# Host smoke: OpenVPN control channel to a VPN Gate TCP server via SOCKS5 (Tor).
# Does NOT test Android OPENTUN — only proves socks-proxy + auth + CONNECTED.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PROFILE="${1:-}"
SOCKS_HOST="${SOCKS_HOST:-127.0.0.1}"
SOCKS_PORT="${SOCKS_PORT:-9050}"
AUTH_USER="${AUTH_USER:-}"
AUTH_PASS="${AUTH_PASS:-}"

if [[ -z "$PROFILE" ]]; then
  for cand in "$ROOT/testdata"/vpngate-tcp-*.ovpn; do
    [[ -f "$cand" ]] || continue
    if "$0" "$cand"; then
      exit 0
    fi
  done
  echo "No VPN Gate profile accepted AUTH/PUSH — refresh testdata"
  exit 1
fi
[[ -f "$PROFILE" ]] || { echo "Missing $PROFILE"; exit 1; }

# Tor SOCKS must already listen (or set SOCKS_PORT to any SOCKS5).
if ! timeout 2 bash -c "echo >/dev/tcp/$SOCKS_HOST/$SOCKS_PORT" 2>/dev/null; then
  echo "No SOCKS at $SOCKS_HOST:$SOCKS_PORT — start Tor or set SOCKS_PORT"
  exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"; kill ${OVPN_PID:-0} 2>/dev/null || true' EXIT
AUTH="$WORKDIR/auth.txt"
printf '%s\n%s\n' "$AUTH_USER" "$AUTH_PASS" >"$AUTH"
CFG="$WORKDIR/runtime.ovpn"
# Strip routes/DNS; force socks; keep certs from original.
python3 - "$PROFILE" "$CFG" "$SOCKS_HOST" "$SOCKS_PORT" "$AUTH" "$AUTH_USER" "$AUTH_PASS" <<'PY'
import sys
src, dst, host, port, auth, user, password = sys.argv[1:8]
text = open(src).read()
lines = []
for line in text.splitlines():
    t = line.strip()
    low = t.lower()
    if low.startswith(("socks-proxy", "http-proxy", "redirect-gateway", "dhcp-option", "route ", "auth-user-pass")):
        continue
    if low.startswith("proto "):
        lines.append("proto tcp4-client")
        continue
    lines.append(line)
lines += [
    f"socks-proxy {host} {port}",
    "nobind",
    "server-poll-timeout 120",
    "connect-retry 10 120",
    "connect-retry-max 2",
    "hand-window 120",
    "resolv-retry 0",
    "auth-retry none",
    "route-nopull",
    'pull-filter ignore "redirect-gateway"',
    'pull-filter ignore "dhcp-option DNS"',
    "verb 3",
]
if user or password:
    open(auth, "w").write(f"{user}\n{password}\n")
    lines.append(f"auth-user-pass {auth}")
open(dst, "w").write("\n".join(lines) + "\n")
PY

echo "Testing $PROFILE via socks $SOCKS_HOST:$SOCKS_PORT"
# Need CAP_NET_ADMIN for tun — if missing, PASS = PUSH_REPLY / Peer Connection Initiated.
LOG="$WORKDIR/ovpn.log"
set +e
timeout 90 openvpn --config "$CFG" --log "$LOG" --daemon ovpn-smoke --writepid "$WORKDIR/ovpn.pid"
OVPN_PID="$(cat "$WORKDIR/ovpn.pid" 2>/dev/null || true)"
for i in $(seq 1 45); do
  if rg -q "Initialization Sequence Completed|PUSH_REPLY|AUTH_FAILED|TLS Error|Connection reset|Cannot ioctl TUNSETIFF" "$LOG" 2>/dev/null; then
    break
  fi
  sleep 2
done
set -e
echo "---- openvpn log (tail) ----"
tail -40 "$LOG" || true
if rg -q "Initialization Sequence Completed" "$LOG"; then
  echo "PASS: control+tun up via SOCKS (host)"
  exit 0
fi
if rg -q "PUSH_REPLY" "$LOG" && rg -q "Cannot ioctl TUNSETIFF" "$LOG"; then
  echo "PASS: control plane via SOCKS (PUSH_REPLY); tun needs root/OPENTUN on Android"
  exit 0
fi
if rg -q "AUTH_FAILED" "$LOG"; then
  echo "FAIL: AUTH_FAILED — leave AUTH empty for VPN Gate, or set provider creds"
  exit 2
fi
if rg -q "TLS Error|Connection refused" "$LOG"; then
  echo "FAIL: transport/TLS — see log"
  exit 3
fi
echo "INCONCLUSIVE — see log"
exit 4
