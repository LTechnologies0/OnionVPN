# OpenVPN over Tor (optional)

OnionVPN can run a **TCP OpenVPN** client whose control channel exits via Tor SOCKS
(`SessionGroup` OPENVPN + `IsolateSOCKSAuth` / credentials `openvpn`/`overtor`).

## Binary (required)

TARGET_ANDROID binaries from F-Droid **OpenVPN for Android** (`de.blinkt.openvpn`):

```bash
./native/openvpn/fetch-ics-openvpn-libs.sh   # → jniLibs/{arm64-v8a,x86_64}/libovpnexec.so + libopenvpn.so
```

Upstream OpenVPN without `TARGET_ANDROID` cannot speak OPENTUN / PROTECTFD — Via OVPN
stays fail-closed. See `NOTICE` (GPL).

## Free test servers (VPN Gate)

Academic public relays ([VPN Gate](https://www.vpngate.net/en/), Univ. of Tsukuba) — **not**
for private traffic; operators may log. TCP configs often need username/password **`vpn`/`vpn`**.

```bash
./native/openvpn/fetch-vpngate-testdata.sh   # → testdata/vpngate-tcp-*.ovpn
# Optional host control-plane check (Tor SOCKS on :9050):
./native/openvpn/smoke-host-socks.sh
```

In the app: Settings → Import `.ovpn` → leave username/password **empty** for most VPN Gate
profiles (only set `vpn`/`vpn` if the server prompts). Enable → restart tunnel.

## Control plane

1. Resolve `remote` via Tor SOCKS `RESOLVE` (no clearnet DNS leak).
2. Rewrite `.ovpn`: `proto tcp-client`, `socks-proxy`, `route-nopull`, ignore DNS/gateway push.
3. Unix management + `management-client` / `management-hold` for NEED-OK / OPENTUN / PROTECTFD / Auth.

## Data plane (OPENTUN)

Socketpair with Android TUN FD semantics; `ALLOW_OVPN` ↔ OpenVPN ↔ `injectToVpnTun`.
`openVpnOverTorUp` only when **CONNECTED + OPENTUN**.

## Onionmasq

Dedicated OVPN SocksPort relayed to the sidecar (`ArtiSocksRoleMux`).
Sidecar SOCKS auth must allow `openvpn`/`overtor` (`socks-sidecar.patch`) — rebuild
`libonionmasq_mobile.so` after changing the patch.

## C Tor

Native torrc `SOCKSPort` with `SessionGroup=OPENVPN` + `IsolateSOCKSAuth`. No role-mux.
Start path waits for that SocksPort before RESOLVE / OpenVPN spawn.
