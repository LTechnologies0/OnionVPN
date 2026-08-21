# Changelog

All notable changes to OnionVPN are documented here.

## [Unreleased]

## [0.3.69] — 2026-08-21

### C Tor / Arti engine correctness
- C Tor live `EntryNodes`/`ExitNodes`/`ExcludeNodes` also SETCONF `StrictNodes` (match torrc).
- Hard recover fail-closed on `DisableNetwork` bounce; wait SOCKS **and** DNSPort before DNSCrypt resume.
- GeoIP download uses probe SocksPort (not apps SessionGroup).
- Live bridge/PT enable from clearnet requires tunnel restart (CTP + cache wipe).
- Arti: Entry/Exclude fail closed; exit country via onionmasq callback; circuit timing Result no longer silent success.
- onionmasq start parses ExitNodes via `TorCountryCatalog` (multi → first + warn).
- Patch: sidecar SOCKS allowlist `openvpn`/`overtor` (rebuild `libonionmasq_mobile.so` for Arti+onionmasq OVPN).

### Always-On / Private Space
- Narrow Always-On reconcile (do not tear Tor on cold Idle Blocking).
- Retry Connected from kill-switch Blocking when uplink VALIDATED (Always-On / space unlock / net flap).
- `notifyCoordinator` retries; Blocking establish uses `nextGeneration`; longer VPN ready wait.
- `USER_UNLOCKED` restores tunnel when Always-On is ours or phase is Blocking.

### Tor country exclusions
- EU / EEA / Schengen federations include Tor GeoIP `{eu}` (relays without a member-state tag).
- Auto-migrate legacy ExcludeNodes lists that covered ≥20 EU members but omitted `{eu}`.

### Wallets / Tor engines
- Settings preset **Wallets** (long MaxCircuitDirtiness) + tip for Cake Wallet-style Electrum/RPC.

### OpenVPN over Tor (optional)
- TCP OpenVPN client via Tor SOCKS SessionGroup OPENVPN (`socks-proxy` + IsolateSOCKSAuth).
- Ships **ics-openvpn** `libovpnexec.so` + `libopenvpn.so` (F-Droid `de.blinkt.openvpn` 0.7.64) — refresh with `native/openvpn/fetch-ics-openvpn-libs.sh` (GPL NOTICE).
- Unix management + OPENTUN socketpair + PROTECTFD; Via OVPN only when CONNECTED **and** OPENTUN attached.
- Pin `remote` via Tor SOCKS RESOLVE; optional auth-user-pass in Settings.
- Onionmasq: dedicated OVPN SocksPort relayed to sidecar.
- Test: VPN Gate TCP samples (`fetch-vpngate-testdata.sh`) + host control-plane smoke (`smoke-host-socks.sh`) — **PASS** PUSH_REPLY via Tor SOCKS; device binary `--version` OK (icsopenvpn).

### Firewall
- Three-way verdicts: **Via Tor** / **Via OVPN** / **Deny** (legacy `ALLOW` → `ALLOW_TOR`).
- Heads-up + prompt UI expose OVPN only when the OVPN-over-Tor tunnel is up.

## [0.3.68] — 2026-08-16

### Arti / onion services
- Native `.onion` via SOCKS: enable `onion-service-client` and `allow_onion_addrs` in patched `libarti_mobile_ex`.
- Reconfigure fail-closed: apply circuit timing / exit country on the live client **before** disk + cached params; propagate exit-country reconfigure errors (no silent success).

### Reliability / leak UX
- Per-flow TUN reject gate for ICMP port-unreachable and TCP RST (Happy Eyeballs / QUIC bursts no longer silent-blackhole under a global 2ms CAS).
- Automap DNS: answer A or NODATA for AAAA/IPv6 queries instead of dropping (faster dual-stack fallback).
- Peer UID miss on API ≥ Q: fail closed in SOCKS UID bridge / Arti role mux.
- Soft validation: `tor.onion.socks5a`; status `allow_onion_addrs` tied to control API.

### Security
- Gate exported `MainActivity` debug start/stop extras behind `BuildConfig.DEBUG`.
- Harden DNSCrypt / PAC / Tor path policy and move `SecureTorHttp` into shared model net helpers.

### Native
- Rebuilt `jniLibs/{arm64-v8a,x86_64}/libarti_mobile_ex.so` (16 KB page aligned) with the above Arti patches.

## [0.3.67] — 2026-08-08

### Performance
- **Baseline Profiles** for Status, tunnel start, and Compose hot paths — packaged as `assets/dexopt/baseline.prof` so ART AOT-compiles them after install (sideload / Graphene / no Play via ProfileInstaller).
- Seeded `baseline-prof.txt` + `startup-prof.txt` (and `baselineProfiles/`) so releases ship AOT hints without a device; optional regenerate: `./gradlew :app:generateBaselineProfile`.
- New `:baselineprofile` macrobenchmark module for connected arm64 regeneration.

### Build / CI hosts
- **ARM64 host builds** (Termux / aarch64 CI): auto-detect native `aapt2` so AGP does not need x86_64 QEMU.
- `scripts/configure-arm-host.sh` + `scripts/gradlew-arm`; optional `gradle/arm-host.local.properties` for `aapt2` override and `org.gradle.java.home` (JDK 21 aarch64).

### Security
- Harden DNSCrypt / PAC path: private-IP and hostname gates (`TorNetPolicy`), PAC HTTP GET/Host/header limits.
- `SecureTorHttp` — no redirects, modern TLS only — for Tor-proxied HTTP used by DoH / Moat-style fetches.
- SOCKS DNS bootstrap / DoH hostname verification tightened.
- GrapheneOS / ARM **MTE**: `android:memtagMode="async"`; `scripts/verify-memtag-manifest.sh`.
- Document 64-bit-only ABI policy (hardened_malloc / extended VA).

### Reliability / UX
- Clear Resources profiler snapshot on tunnel stop; hide Resources chips unless the tunnel is up (no stale RSS/CPU on Idle).
- In-process VPN teardown / `START_NOT_STICKY` on STOP/DESTROY to reduce leftover hev threads racing Always-On VPN.
- Debug-only tunnel start path for MCP/adb testing without BAL_BLOCK broadcast issues.

### Tests
- Expanded `DnsCryptResolverTest` / `DnsCryptSocksBridgeTest` for the new network policy gates.
