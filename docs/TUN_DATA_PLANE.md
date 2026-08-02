# TUN data planes

## HEV_SOCKS (default without native onionmasq / C Tor)

```
Apps → VpnService TUN → TunDnsMux → hev-socks5-tunnel → SocksUidBridge → Tor SOCKS
```

Works with C Tor and Arti (arti-mobile). DNSCrypt divert on TunDnsMux; upstream via Tor SOCKS.

## ONIONMASQ (Arti preferred when `libonionmasq_mobile.so` present)

Tor Project **onionmasq**: TUN packets (via TunDnsMux socketpair) → smoltcp → **arti-client** in-process.

```
Apps → TUN → TunDnsMux → DNSCrypt (UDP/53)
                      └→ socketpair → OnionMasq.start(fd) → Arti TorClient
DNSCrypt upstream → SOCKS IsolationToken
  • target: onionmasq SOCKS sidecar (same TorClient; getSocksSidecarPort)
  • interim: arti-mobile SOCKS + DNSPort (dual TorClient until orchestrator cutover)
```

### Requirements

1. Settings → Tor engine = **Arti** (selecting Arti auto-picks onionmasq when the `.so` exists)
2. Native `libonionmasq_mobile.so` under `jniLibs` (build: [native/onionmasq/README.md](../native/onionmasq/README.md))
3. `OnionVpnService` implements `ISocketProtect` + `OnionMasq.bindVPNService` for `protect()`

### Observability (Tor VPN parity)

- `BootstrapEvent` → tunnel ready (`OnionVpnService.onionmasqReady`)
- `NewConnectionEvent` / hops → `OnionmasqCircuitRepository` + Status → **App circuits (onionmasq)**
- `refreshCircuits()` / `refreshCircuitsForApp(uid)` → New identity / per-app NEWNYM
- `NewDirectoryEvent.relaysByCountry` → exit-country catalog hint in Settings
- `getBytes*ForApp` → per-app bandwidth on the circuits panel
- Connection / fail events → Tor log tab via `TunnelLogBuffer`

### Anti-leak

OnionVPN keeps fail-closed routing (no Tor VPN `allowFamily`). Own package stays disallowed from the VPN; onionmasq/Arti sockets use clearnet uplink via `protect`. Tor-native apps (Orbot, Tor Browser, …) are `setExcludedUids` so they are not double-proxied.

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

### Capability matrix

| Engine / plane | Circuits UI | NEWNYM | DNSCrypt SOCKS |
|----------------|-------------|--------|----------------|
| C Tor + hev | ControlPort | SIGNAL NEWNYM | SessionGroup port |
| Arti + hev | limited | arti-mobile restart | ArtiSocksRoleMux |
| Arti + onionmasq | onionmasq events | `refreshCircuits*` | sidecar (interim: arti-mobile) |
