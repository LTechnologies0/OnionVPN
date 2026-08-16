# Changelog

All notable changes to OnionVPN are documented here.

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
