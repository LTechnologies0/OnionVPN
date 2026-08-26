# OpenVPN over Tor (optional)

OnionVPN can run a **TCP OpenVPN** client whose control channel exits via Tor SOCKS
(`SessionGroup` OPENVPN + `IsolateSOCKSAuth` / credentials `uopenvpn`/`popenvpn`).

## Binary (required)

TARGET_ANDROID binaries from F-Droid **OpenVPN for Android** (`de.blinkt.openvpn`):

```bash
./native/openvpn/fetch-ics-openvpn-libs.sh   # → jniLibs/{arm64-v8a,x86_64}/libovpnexec.so + libopenvpn.so
```

Upstream OpenVPN without `TARGET_ANDROID` cannot speak OPENTUN / PROTECTFD — Via OVPN
stays fail-closed. See `NOTICE` (GPL).

## Test profiles (optional)

Public TCP OpenVPN samples for CI/smoke (e.g. academic relays) — **not** for private
traffic. Import any standard `.ovpn`; auth follows OpenVPN man (inline block or Settings).

```bash
./native/openvpn/fetch-vpngate-testdata.sh   # → testdata/*.ovpn samples
# Optional host control-plane check (Tor SOCKS on :9050):
./native/openvpn/smoke-host-socks.sh
```

## Control plane

1. Resolve **every** `remote` hostname via Tor SOCKS `RESOLVE` (no clearnet DNS; multi-remote keeps distinct IPs).
2. Rewrite `.ovpn`: `proto tcp4-client`, `socks-proxy` **without** authfile (ics-openvpn 2.7 VER=5 bug; isolation = SessionGroup),
   Tor timeouts (`server-poll-timeout`/`hand-window` ≥ SocksTimeout), `route-nopull`,
   ignore DNS/gateway/`ping*` push, `script-security 0`.
3. Unix management + `management-client` / `management-hold` for NEED-OK / OPENTUN / PROTECTFD / Auth.
4. Wait until management socket is listening before spawning OpenVPN (no fixed sleep).

## Data plane (OPENTUN)

Socketpair with Android TUN FD semantics; `ALLOW_OVPN` ↔ OpenVPN ↔ `injectToVpnTun`.
`openVpnOverTorUp` only when **CONNECTED + OPENTUN**. Soft-restarts clear Via OVPN until
CONNECTED returns; the OPENTUN pump stays up (`persist-tun`).

## Onionmasq

Dedicated OVPN SocksPort relayed to the sidecar (`ArtiSocksRoleMux`).
Sidecar SOCKS auth must allow OpenVPN credentials (`uopenvpn`/`popenvpn` via `u*`→`p*`,
or literal `openvpn`/`overtor` after rebuilding with `socks-sidecar.patch`).
`libonionmasq_mobile.so` after changing the patch.

## C Tor

Native torrc `SOCKSPort` with `SessionGroup=OPENVPN` + `IsolateSOCKSAuth`. No role-mux.
Start path waits for that SocksPort before RESOLVE / OpenVPN spawn.
