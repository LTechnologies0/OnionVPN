# Changelog

All notable changes to OnionVPN are documented here.

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
