# TUN data planes

## HEV_SOCKS (default without native onionmasq / C Tor)

```
Apps → VpnService TUN → TunDnsMux → hev-socks5-tunnel → SocksUidBridge → Tor SOCKS
```

Works with C Tor and Arti (arti-mobile). DNSCrypt divert on TunDnsMux; upstream via Tor SOCKS.

## ONIONMASQ (Arti preferred when `libonionmasq_mobile.so` present)

Tor Project **onionmasq**: TUN packets (via TunDnsMux socketpair) → smoltcp → **arti-client** in-process.

**Single TorClient** (Tor VPN parity — no parallel arti-mobile):

```
Blocking TUN (kill-switch)
  → Connected TUN → TunDnsMux → socketpair → OnionMasq.start(fd)
       → wait BootstrapEvent ready_for_traffic ∧ pct≥100 (sticky; Tor VPN gate)
       → SOCKS sidecar (same TorClient; IsolationToken by user; password allowlist)
  → SocksDnsBootstrapRelay :torDnsPort → sidecar → DoH https://1.1.1.1/dns-query (not :53)
  → DNSCrypt proxy=@sidecar bootstrap=@relay
  → Validating → Connected UI
```

```
Apps → TUN → TunDnsMux → DNSCrypt (UDP/53 IPv4+IPv6 ULA `fd00:8:8:8::1`)
                      └→ socketpair → OnionMasq.start(fd) → Arti TorClient
DNSCrypt / probes → onionmasq SOCKS sidecar (dnscrypt[-nN] / probe + role passwords)

App streams use IsolateSOCKSAuth tokens `u{uid}` / `u{uid}-n{epoch}` (epoch bumps on NEWNYM —
KeepAliveIsolateSOCKSAuth must not stick pre-NEWNYM identity). DNSCrypt stays on a separate
SessionGroup / `dnscrypt[-nN]` token (Whonix: DNS ≠ app circuits). Apps SocksPort omits
`IsolateClientAddr` (every bridge client is 127.0.0.1). PAC refuses CONNECT when UID is unknown
(no shared `pac` pool).
```

No live MaxCircuitDirtiness on onionmasq (Tor VPN same gap) — UI hides Arti Ext timing;
exit country via `setCountryCode` + NEWNYM via `refreshCircuits` (~10.5s rate limit).

### Requirements

1. Settings → Tor engine = **Arti** (selecting Arti auto-picks onionmasq when the `.so` exists)
2. Native `libonionmasq_mobile.so` under `jniLibs` (build: [native/onionmasq/README.md](../native/onionmasq/README.md))
3. `OnionVpnService` implements `ISocketProtect` + `OnionMasq.bindVPNService` for `protect()`
4. Patched SOCKS sidecar (`native/onionmasq/socks-sidecar.patch`)

### Observability (Tor VPN parity)

- `BootstrapEvent` → tunnel ready (`OnionVpnService.onionmasqReady`)
- `ConnectivityHandler` → `setInternetConnectivity` (uplink dormancy)
- `NewConnectionEvent` / hops → `OnionmasqCircuitRepository` + Status → **App circuits (onionmasq)**
- `refreshCircuits()` / `refreshCircuitsForApp(uid)` → New identity / per-app NEWNYM
- `NewDirectoryEvent.relaysByCountry` → exit-country catalog hint in Settings
- `getBytes*ForApp` → per-app bandwidth on the circuits panel
- Connection / fail events → Tor log tab via `TunnelLogBuffer`

### Anti-leak

OnionVPN keeps fail-closed routing (no Tor VPN `allowFamily`). Own package stays disallowed from the VPN; onionmasq/Arti sockets use clearnet uplink via `protect`. Tor-native apps (Orbot, Tor Browser, …) use a dual bypass: **hev / all planes** — `VpnService.Builder.addDisallowedApplication` (Orbot BYPASS, **signature-pinned** via `TorNativeAppUids`); **onionmasq** — additionally `setExcludedUids` before `OnionMasq.start` (clearnet via `protect`). PACKAGE_ADDED/REMOVED/REPLACED for Tor-native candidates **rebinds Connected** on hev (disallow list is establish-time only) and refreshes onionmasq UIDs. **INCLUDE × Android lockdown** refuses Connected establish (Builder cannot mix allow + disallow; lockdown would offline BYPASS apps — never Orbot #774 skip-BYPASS). DNSCrypt bootstrap never uses system DNS (`SocksDnsBootstrapRelay` over sidecar on onionmasq; Tor DNSPort on C Tor).

### Lifecycle (native abort hazard)

`libonionmasq_mobile.so` / `libarti_mobile_ex.so` use `panic=abort`. JNI helpers that call
`OnionmasqMobile::get()` **kill the process** if `OnionMasq.init()` has not succeeded —
including `isRunning`, `closeProxy`, `refreshCircuits*`, `getBytes*ForApp`, `setCountryCode`,
`setExcludedUids`, `setInternetConnectivity`. `runCatching` cannot catch SIGABRT.

Rules:
1. `OnionmasqTunForwarder.start()` calls `stop()` before `init()` — gate stop on Kotlin
   `proxyOwned` only (never probe native `isRunning` pre-init).
2. UI / Settings / NEWNYM must check `OnionMasq.isInitialized()` (+ `isRunning()` for commands)
   before any onionmasq JNI.
3. Java `OnionMasq.*` soft-guards every JNI entry; rebuild `.so` with
   `native/onionmasq/safe-uninit-jni.patch` for native-side try_get.
4. TunDnsMux / UID forwarder must `Os.dup` before wrapping the same FD in both FIS and FOS.
5. Arti JNI must never `.expect` / `panic!` on the boundary (source under `third_party/arti-mobile-ex`).
6. `awaitProtectBinder` before `OnionMasq.start`; `ConnectivityHandler.register` for the proxy lifetime.
7. Ship `libonionmasq_mobile.so` (not legacy `libonionmasq.so` name in UI copy). `.so` >50MB → Git LFS.
8. `setTurnServerConfig` = WebRTC unsupported (UDP blackhole); do not half-wire prefs.

### Capability matrix

| Engine / plane | Circuits UI | NEWNYM | DNSCrypt SOCKS |
|----------------|-------------|--------|----------------|
| C Tor + hev | ControlPort | SIGNAL NEWNYM | SessionGroup port |
| Arti + hev | limited | arti-mobile restart | ArtiSocksRoleMux |
| Arti + onionmasq | onionmasq events | `refreshCircuits*` | SOCKS sidecar (single TorClient) |

### Foreground services (dual specialUse)

Android 14+ VPN apps often run **two** FGS entries: the coordinator
(`TunnelForegroundService`, subtype “Tor and DNSCrypt VPN tunnel coordinator”) and
`OnionVpnService` (BIND_VPN_SERVICE + specialUse “Anonymous VPN tunnel…”). Both declare
`foregroundServiceType=specialUse` with distinct PROPERTY_SPECIAL_USE_FGS_SUBTYPE strings —
required by the VPN FGS guide; do not collapse into one process slot without re-auditing
Always-on / revoke paths.
