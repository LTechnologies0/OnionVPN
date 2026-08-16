# CVE inventory (network / crypto natives)

Track known public CVEs against OnionVPN’s networked components.
Status values: **Mitigated** (pin includes fix), **N/A** (not reachable in this app), **Watch** (awaiting upstream tag / rebuild), **Open** (action needed).

Last reviewed: 2026-08-16.

## Tor (`libtor.so`)

| Pin | Value |
|-----|--------|
| Release tag | `tor-0.4.9.11-dev+staticz-20260808b` ([`gradle/native-versions.properties`](../gradle/native-versions.properties)) |
| Upstream | `tor-0.4.9.11` (`tpo/core/tor`) |
| Build branch | Gedsh `prod-0.4.9` (includes 0.4.9.11 + TROVE-2026-025/026 / #41297) |

| CVE / TROVE | Topic | Status |
|-------------|--------|--------|
| CVE-2026-44599 / TROVE-2026-008 | BEGIN_DIR via conflux legs | **Mitigated** (≥ 0.4.9.7) |
| CVE-2026-44597 / TROVE-2026-011 | OOB read END/TRUNCATE cells | **Mitigated** (≥ 0.4.9.7) |
| TROVE-2026-025 | Conflux UAF (LINK before BEGIN) | **Mitigated** (0.4.9.10+) |
| TROVE-2026-026 | Conflux recovery-leg UAF | **Mitigated** (0.4.9.11) |
| Tor #41297 | Onion HS rendezvous RP MITM race | **Mitigated** (0.4.9.11) |

## OpenSSL (static in `libtor.so`)

| Pin | `openssl-3.6.3` (Tor-Android-build-script) |

| CVE | Topic | Status |
|-----|--------|--------|
| OpenSSL 3.6.3 High/Mod set (2026-06) | PKCS7 UAF, CMS, QUIC client/server NULL, etc. | **Mitigated** |
| CVE-2026-14456 | QUIC *server* unbounded pending channels | **N/A** (Tor client does not run OpenSSL QUIC listener) — bump to **3.6.4** when tagged (**Watch**) |
| CVE-2026-54876 | OCSP client memory leak | **Watch** (Low; include with 3.6.4 rebuild) |

## DNSCrypt (`libdnscrypt-proxy.so`)

| Pin | `dnscrypt.commit=434f38d1e27f1a3dfc9de9e3ba3aea5c647e4290` (2026-05-30) |

| CVE / issue | Topic | Status |
|-------------|--------|--------|
| CVE-2024-36587 | Service-install binary overwrite (Unix/Windows) | **N/A** (Android app-private `ProcessBuilder`, not system service) |
| ODoH short plaintext panic (`2d7227c`, 2026-04-16) | OOB slice on decrypt | **Mitigated** (vendored commit is **ahead** of fix) |

## Pluggable transports / other natives

| Component | Pin notes | CVE posture |
|-----------|-----------|-------------|
| Lyrebird / Conjure | From Tor-Android-build-script release | Track via PT upstream + rebuild workflow |
| hev-socks5-tunnel | sockstun extract | No public CVE matched this review |
| Arti / onionmasq | Maven / local build | Track Tor Project Arti advisories separately |

## Compression pins (Tor-Android-build-script → next rebuild)

| Library | Old → New | Notes |
|---------|-----------|--------|
| zstd | v1.4.9 → **v1.5.7** | Stale pin; rebuild natives to ship |
| xz | v5.2.4 → **v5.8.3** (`tukaani-project/xz`) | Avoid 5.6.0/5.6.1 tarballs (CVE-2024-3094); 5.8.3 includes CVE-2025-31115 |
| zlib | v1.3.1 → **v1.3.2** | Rebuild natives to ship |

Until a new `tor.release.tag` is published and fetched, OnionVPN still ships the previous staticz build (Tor/OpenSSL already current; compression bumps pending rebuild).

## App-layer mitigations (no CVE ID)

See [ANTI_LEAK_CHECKLIST.md](ANTI_LEAK_CHECKLIST.md): UDP/STUN/WebRTC/ICMP/QUIC blackhole, DNSCrypt-over-SOCKS, no `allowBypass`, kill-switch, GrapheneOS `memtagMode=async`.

CI gates:
- `scripts/verify-jniLibs-standalone.sh` — NEEDED ⊆ Bionic + liblog
- `scripts/verify-native-cve-pins.sh` — Tor ≥ 0.4.9.11, OpenSSL ≥ 3.6.3, DNSCrypt commit match
- `scripts/verify-memtag-manifest.sh` — `memtagMode=async`

TUN parsers (`IpPacketParser`, `DnsPacketParser`, `LeakPacketFilter`) fail-closed on truncation, oversize `length`, compression loops, and non-TCP/DNS UDP.

## Gradle / Maven (app process)

| Component | Pin | Status |
|-----------|-----|--------|
| OkHttp | **5.4.0** | OSV clean as of 2026-08-16; all Tor HTTPS clients use `SecureTorHttp.applyTorClientHardening()` (`:core:model`) |
| arti-mobile | **1.7.0.1** | Track Tor Project Arti advisories |

`SecureTorHttp` enforces: no redirects, `ConnectionSpec.MODERN_TLS` only (TLS MitM / redirect CVE class).

## Related repos

| Repo | Action |
|------|--------|
| Tor-Android-build-script | Pins zlib **v1.3.2** / zstd **v1.5.7** / xz **v5.8.3** — next release feed updates `tor.release.tag` |
| SecureMessenger | Netty (IRC) — separate app |
| kotlin-tor | Experimental; not used by OnionVPN production path |
