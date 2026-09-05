# Changelog

All notable changes to OnionVPN are documented here.

## [Unreleased]

## [0.3.75] — 2026-09-05

### Firewall / OVPN plane stickiness
- Automap/`.onion` never Via SoftEther (engine stickyIntent + TunDnsMux Tor divert).
- Persist ALLOW_OVPN intent in decisionCache; flowCache stores live plane (no mid-TCP Tor↔OVPN flip).
- Mid-flow sticky rule/decision and UID-miss fallback never invent SoftEther (`ALLOW_OVPN` → Tor).
- Failed OVPN `offer` drops (no mid-flow Tor flip); unhealthy OVPN status is Starting not Up.
- TEMPORARY: no sticky decisionCache; schedule forget flowKey+tupleKey at expiry (StateFlow never emits on wall-clock).
- Rules collect skips dest-wipe for TEMPORARY; SESSION/PERMANENT stamp tupleKey for mid-flow UID-miss.
- SOCKS/PAC prompts hide Via OVPN (`socksPlane`); answers force Tor.
- Disable OpenVPN-over-Tor / clear missing profile demotes ALLOW_OVPN→ASK and clears Via OVPN rules.
- answerPrompt Automap demotion uses matched request only (no queue-rotate race).
- FirewallCacheKeys flow/tuple: mix IPv6 src/dst host strings (ints stay 0 → collisions).

### OpenVPN-over-Tor
- OvpnIpNat: separate TCP/UDP conntrack maps (XOR proto into IP bits collided across remotes).
- Config rewrite: strip all `proto` → one `tcp4-client`; `tcp6`/`tcp-client` → `tcp`; strip compress + `allow-compression no` (VORACLE).
- PROTECTFD cancel on protect fail; Auth `writeCmd` redacts; SNAT/DNAT logs length-only.

### Tor ControlPort / TUN / PAC
- Little-t: reconnect ControlSocket after reader death (`ensureClassicControlConnected` in health-lite, `requireClassic`, NEWNYM).
- TunDnsMux: track PFD.dup owners and close on stop; IPv6 DNS snoop srcPort offset 40.
- DnsCryptSocksBridge: refuse SOCKS CONNECT to IPv6 literals (DNSCrypt A-only).

### OPSEC / sensitive leakage
- ExitIpValidator / vpn.address.not.public details: counts only (no raw exit/ISP/link IPs).
- TorControlEventFormatter truncates `$HEX40` fingerprints before TunnelLogBuffer.
- ACTION_START Intent: bridges, Entry/Exit/Exclude, OVPN Auth never on extras (DataStore + process-local bridge handoff).
- Firewall prompt notif: VISIBILITY_SECRET + no dest/DPI on shade.
- SocksUidBridge / onionmasq connection logs: uid (+ hops/err) only — no dest host:port.
- OpenVPN Tor-RESOLVE pin log: success only (no host/IP).

## [0.3.74] — 2026-09-04

### .onion on C Tor and Arti
- Automap TCP divert on onionmasq → SocksUidBridge → sidecar SOCKS5A; rebuild
  `libonionmasq_mobile.so` with `connect_to_onion_services` + `allow_onion_addrs`.
- Arti + hev selectable (arti-mobile); onionmasq validation requires Automap upstream == sidecar.

### Consistency (firewall / planes / ports)
- Blocking establish clears SOCKS publish gate (`stopForwarder`) — no stale hevSocksPort on blackhole TUN.
- SOCKS decision keys namespaced (`PACL`) — PAC/hev ALLOW_TOR no longer poisons TUN Via OVPN.
- CircuitLifecycle gated on `classicControlPlane` (not Arti `circuitInspection`).
- ArtiSocksRoleMux hot-swaps upstream on sidecar rebind (OpenVPN listen FD kept).
- Arti Settings copy: “role-mux SocksPorts” (not native SessionGroup).
- Via OVPN ASK when OVPN down stores ALLOW_TOR (was DENY blackhole).
- Sticky ALLOW_OVPN rules/cache demote to Tor when SNAT/health is down (`coerceLiveOvpn`).
- `setTorSocksUpstream(0)` clears published `hevSocksPort` to -1; positive publish only when bridge updater exists.
- onionmasq Connected wait is DNSCrypt-listen-aware; socks stay -1 until sidecar wired.
- startForwarder failure / onFatal clear ports → -1 (fail-closed).
- `waitForConnected` / `hevPortsMatch` / `planePortsMatch` require `tunForwarderAlive`.
- onionmasq forwarder rebind rewires sidecar (Automap + DNSCrypt + PAC); Tor-native package rebind is HEV-only.
- Downtime restore on onionmasq uses live sidecar only (no stale remapped port).
- Automap: firewall DENY when hostname unknown; SYN brief cache retry; remap cancels ASK.
- SOCKS flow-cache entries go through `coerceSocksVerdict` (OVPN demotion).
- Hard-kill IDs: `uid.forwarder.wiring`, `onionmasq.plane.wiring` (drop unused hev.* aliases).
- Debug tunnel start resolves plane via `TunDataPlaneFactory` (no onionmasq without `.so`).
- Arti chip defaults to onionmasq when native present; hev remains explicit opt-in.
- Hide dead FakeDNS Settings mode; CLOSECIRCUIT 552 → debug (no Error spam).

## [0.3.73] — 2026-08-27

### MITM hardening (in-scope)
- OpenVPN import/start refuse profiles without CA or `peer-fingerprint` /
  `verify-x509-name` / `verify-hash` (MitM-friendly `.ovpn` rejected).
- DNSCrypt: `doh_servers = false` — resolver authenticity via DNSCrypt stamps, not
  system-TLS DoH.
- Global Android HTTP proxy fails Connected / trips kill-switch (local MitM risk).
- Moat bridge fetch defaults to Tor SOCKS (`moatRequestViaTor = true`).
- Threat model: OnionVPN mitigates clearnet DNS/DoT bypass, OVPN without server
  trust, app HTTPS cleartext, and local HTTP proxy while TUN+Tor are up. Out of
  scope: Wi‑Fi ARP/Evil Twin L2, ISP BGP, physical taps, IMSI catchers, SCADA/IoT,
  and third-party apps’ TLS stacks.

## [0.3.72] — 2026-08-26

### OpenVPN-over-Tor / Arti SOCKS
- Arti role mux: OpenVPN port is a SOCKS5 terminating shim (`SocksAuthInjectingRelay`) — NO-AUTH toward ics-openvpn, USER/PASS for the Java auth probe, IsolateSOCKSAuth (`uopenvpn`/`popenvpn`) toward Arti. Fixes `unexpected auth` / socks-error storms that blocked nested OpenVPN TLS over Arti.
- Fail-closed after repeated `unexpected auth` / soft `socks-error` (avoids 120s reconnect loops if the shim regresses).
- Inject `remote-cert-tls server` when the profile has a CA but no server-cert verification method (closes OpenVPN MitM warning). Proven on Waydroid x86_64 + Arti: `VERIFY OK` + `CONNECTED` + Via OVPN UP.
- Standardize auth on OpenVPN man for every profile (no provider product branches): import fills Settings from inline `<auth-user-pass>` only; bare/`#auth-user-pass` never invents defaults; same auth-user-pass file + management Auth path; AUTH_FAILED with Settings creds retries empty once.

### DNSCrypt
- Default Tor-friendly extras are `cs-de`/`cs-nl` after the user’s pick (no longer prepend `adguard-dns` — avoids non-standard provider / XChaCha20 notices at boot).

## [0.3.71] — 2026-08-26

### OpenVPN-over-Tor data path
- SoftEther data-plane health: SNAT without DNAT replies for 20s demotes Via OVPN to Tor (control may still look CONNECTED); restores when replies resume. Status detail shows the demotion.
- Firewall: “Clear Via OVPN rules” drops sticky SoftEther routes without leaving the screen.
- SoftEther/VPN Gate: omit `auth-user-pass` file (cert-only); answer Need Auth with empty credentials when Settings blank (invented vpn/vpn broke soft-reconnect after CONNECTED). AUTH_FAILED after a prior CONNECTED demotes Via OVPN without killing the process.
- OPENTUN uses AF_UNIX **SOCK_DGRAM** (packet TUN), not `ParcelFileDescriptor.createSocketPair()` (SOCK_STREAM). Stream coalesced IP frames → SoftEther SecureNAT garbled TCP / browser HTTPS `ERR_CONNECTION_RESET` while BYTECOUNT looked fine.
- SNAT/DNAT VpnService `10.8.0.2` ↔ SoftEther IFCONFIG client IP on the OPENTUN socketpair. Without this, Via OVPN wrote foreign sources into SoftEther net30 → SecureNAT RST (`ERR_CONNECTION_RESET`) while control/BYTECOUNT still looked healthy.
- `mssfix 800` (was 1200) for TCP-over-Tor + SoftEther nesting so TLS ClientHello fits without SecureNAT RST.
- Firewall: changing default away from Allow-via-OVPN clears sticky ALLOW_OVPN caches **and** permanent Via OVPN rules (otherwise SoftEther RSTs keep hitting Tor-path browsers after Settings flip).
- SOCKS plane: `ALLOW_OVPN` demotes to Tor (never DENY) — hev cannot carry OVPN; old coerce→DENY RST'd browsers whenever default/rule was Via OVPN but traffic hit SOCKS (SoftEther down / mid-flow).
- Clearnet IPv6 TCP blackhole: silent drop (not RST) so Happy Eyeballs can complete on IPv4; RST was killing HTTPS while HTTP still worked.
- SoftEther inbound: inject only SNAT-tracked flows (drop keepalives/stale RSTs) so OVPN chatter cannot RST Tor-path TCP on the shared VpnService TUN.
- HEV SOCKS re-check: unknown UID on ASK default fail-opens after TUN SYN (Waydroid WebView UID race).
- SocksUidBridge: trust **loopback** peers when `getConnectionOwnerUid` misses (Waydroid) — old fail-closed treated hev as foreign and RST'd every HTTPS CONNECT while raw Tor SOCKS curl still worked.

### Welcome dialog
- First-launch popup explains purpose, features, and recommends installing OnionVPN in an Android Private Space; reopen from Settings → About. Release auto-start waits until Got it.

### VPN establish / OS lockdown
- Pass `requireOsLockdown` on Connected VPN intent (`TunnelVpnBridge` → `OnionVpnService`). Omitting it used `TunnelPreferences` default `true` and blocked Waydroid/debug Connected even when DataStore had lockdown off.

### Build-variant preference defaults
- Debug APK: `allowAdbClearnetLeak` On (UI visible); Off by default for app lock, no-logs, OS lockdown, auto-start (launch/boot), firewall; per-app mode defaults to EXCLUDE (not “All apps”).
- Release APK: fail-closed — app lock, no-logs, OS lockdown, auto-start launch+boot, firewall, per-app ALL On; ADB clearnet leak forced Off and removed from Settings.

### DNSCrypt-over-Tor / firewall planes
- SocksUidBridge: never SOCKS5A clearnet hostname to Tor — pin via DNSCrypt A (cache or live stub); fail-closed if DNSCrypt unavailable. IPv6 clearnet CONNECT without A also fail-closed.
- Firewall `SocksConnectPlane` labels PAC vs hev UID bridge; both call `allowSocksConnect` before Tor dial.
- DNSCrypt `blocked_names`: `*.onion` / `*.exit` defense-in-depth (TunDnsMux still routes onion to Tor DNSPort).

### OpenVPN-over-Tor
- Deterministic lifecycle: session id invalidates stale watchdog/log/fatal; management listen latch (no sleep race); awaitReady = 120s aligned with watchdog; destroyForcibly after soft destroy.
- Via OVPN clears on RECONNECTING/WAIT/EXITING until CONNECTED returns; OPENTUN pump kept across soft-restarts.
- Pin **each** `remote` hostname via Tor RESOLVE (multi-remote safe); strip scripts/plugins; `script-security 0`.
- Sync profile-on-disk vs prefs at tunnel start; Status shows Via OVPN chip + detail.
- Fix management NEED-OK parser for ics-openvpn `Need 'IFCONFIG' confirmation MSG:…` (was acking type `Need`, blocking OPENTUN).
- Workaround ics-openvpn 2.7 SOCKS bug: omit `socks-proxy` authfile (upstream checks RFC1929 reply VER=5; Tor sends VER=1 → false refusal). Isolation via dedicated SessionGroup SocksPort; Java RESOLVE/probe still use `uopenvpn`/`popenvpn`.
- Fix SOCKS auth refused on onionmasq allowlist mismatch: use `uopenvpn`/`popenvpn` for Java SOCKS clients. Stops reconnect storm after repeated auth refusals.
- Drop deprecated `socks-proxy-retry`; Tor-tuned timeouts (`server-poll-timeout 120`, `hand-window 120`, `connect-retry 10 120`, `connect-retry-max 4`, `ping`/`ping-restart` for Tor RTT).
- Align `tun-mtu 1280` + `mssfix 800` with VpnService MTU + Tor/SoftEther overhead; ignore aggressive server `ping-restart` pushes.
- SOCKS auth probe before spawn; abort on management `AUTH_FAILED` / password verification failure; awaitReady/watchdog 120s.
- Spec alignment ([socks-extensions](https://spec.torproject.org/socks-extensions), path-spec): `proto tcp4-client`, `resolv-retry 0`, `auth-retry none`, `persist-remote-ip` (Tor RESOLVE pin + no clearnet re-resolve).
- `management-query-passwords` so Android Auth works without console TTY.

### DNSCrypt-over-Tor
- Spec + dnscrypt-proxy Tor notes: explicit `http3`/`http3_probe`/`odoh_servers` off; `dnscrypt_servers` on.
- Fix query `timeout` 45s → 20s (must stay under TunDnsMux 25s); `timeout_load_reduction = 0`; `lb_strategy = p2` + `lb_estimator = false` (avoid IsolateDest* circuit storm); `keepalive = 60`.

## [0.3.70] — 2026-08-24

### Waydroid / Arti + OpenVPN-over-Tor stability
- Arti: fail-closed UID trust for loopback SOCKS mux under Waydroid when `getConnectionOwnerUid` misses.
- Arti: readiness gate for DNSCrypt `force_tcp` now uses both TCP DNS bootstrap probes and native `resolveHostname` fallback.
- OpenVPN-over-Tor: refresh “Via OVPN” firewall prompt when OPENTUN becomes usable; stronger runtime sequencing (SocksPort + CONNECTED/OPENTUN).
- OpenVPN-over-Tor config: force TCP remote + reject UDP-only profiles; management/OPENTUN + `PROTECTFD` wiring remains fail-closed.

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
- **Stability:** load OVPN prefs from DataStore at tunnel start; wait SocksPort + await CONNECTED/OPENTUN; force `remote … tcp`; reject UDP-only; refresh firewall prompt when Via OVPN becomes available; assets `pie_openvpn` fallback.

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
