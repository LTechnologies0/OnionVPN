# OnionVPN

Privacy-focused Android VPN that routes **all device traffic through Tor**, with **DNSCrypt** for app DNS (over Tor SOCKS by default; FakeDNS / SOCKS5A as a settings fallback). Inspired by InviZible and Mullvad-style leak protection.

**Package:** `ltechnologies.onionphone.onionvpn`  
**Min SDK 26 · Target / Compile SDK 37 · Java/Kotlin 21 · Jetpack Compose**

### What it does

| Feature | Description |
|---------|-------------|
| Tor tunnel | Full-device VPN via hev-socks5-tunnel → Tor SOCKS; kill switch blocks traffic when the tunnel is down |
| DNSCrypt | App DNS resolved through DNSCrypt (upstream via Tor); TunDnsMux on `10.8.0.1` |
| Interactive firewall | OpenSnitch-style Accept / Deny for new outbound connections (notification + prompt, FIFO queue, permanent / session / temporary rules) |
| Domain threat lists | HaGeZi lists colour destinations on prompts: 🟢 safe (unlisted), 🟠 ads/tracking/telemetry, 🔴 malware/C2 — updates prefer Tor when the tunnel is up |
| App lock | Lock the UI without stopping the tunnel or kill switch |
| Tor tuning | Circuit rotation presets, stream isolation modes, editable `torrc` / `dnscrypt-proxy.toml` |
| Tor engine | Dual backend: **C Tor** (`libtor.so`, default) or **Arti** (`arti-mobile` and/or **onionmasq** TUN) |
| TUN data plane | **hev-socks5** (C Tor / Arti fallback) or **onionmasq** (Arti preferred when `libonionmasq_mobile.so` is present) |
| Circuit UI | Onionmasq path: per-app hops, NEWNYM-per-app, exit directory from `NewDirectoryEvent` |

## Architecture

| Layer | Role |
|-------|------|
| Tor | SOCKS + DNSPort (ephemeral ports), SafeSocks depending on DNS mode |
| Arti (opt-in) | In-process Rust Tor via `arti-mobile` and/or onionmasq; capability-gated ControlPort gaps |
| onionmasq | When selected: TUN → smoltcp → arti-client; SOCKS sidecar for DNSCrypt IsolationTokens (see `docs/TUN_DATA_PLANE.md`) |
| DNSCrypt | App DNS via TunDnsMux; upstream via Tor SOCKS; bootstrap via Tor DNSPort |
| VPN | `OnionVpnService` + hev **or** onionmasq; client `10.8.0.2`, DNS `10.8.0.1` |
| Firewall | `InteractiveFirewallEngine` on the TUN; DNS hostname cache + local reputation DB (HaGeZi / URLhaus / Yoyo / uAssets) for prompt UI |

Modules: `app`, `baselineprofile`, `core:model`, `core:tor`, `core:dnscrypt`, `core:vpn`, `core:validation`.

## Build

```bash
# Always fetch natives if missing (arm64-v8a + x86_64)
./scripts/fetch-native-binaries.sh

# Debug (device ABI)
./gradlew :app:assembleDebug -Ponionphone.devAbi=arm64-v8a

# Release splits (arm64-v8a, x86_64)
./gradlew :app:assembleRelease
```

Requires JDK 21 and Android SDK. Create `local.properties` with `sdk.dir=...` (not committed).

### Baseline Profiles (AOT after install)

Seeded rules under `app/src/main/baselineProfiles/` cover Status, tunnel start, Compose, and VPN/Tor/DNSCrypt hot paths. `profileinstaller` compiles them on first run (sideload / Graphene / no Play).

```bash
# Optional: regenerate on a connected arm64 device (not required for normal builds)
./gradlew :app:generateBaselineProfile
```

`automaticGenerationDuringBuild` is off so CI without a device still ships the seeded profiles.

### ARM64 host builds (Termux / aarch64 CI)

AGP’s Maven `aapt2` is `linux-x86_64` and otherwise needs QEMU. On aarch64:

```bash
./scripts/configure-arm-host.sh   # writes gradle/arm-host.local.properties (gitignored)
./scripts/gradlew-arm :app:assembleDebug -Ponionphone.devAbi=arm64-v8a
```

Or copy `gradle/arm-host.local.properties.example` → `gradle/arm-host.local.properties` and set a native `aapt2` plus optional `org.gradle.java.home` (aarch64 JDK 21). `settings.gradle.kts` also auto-detects `/usr/bin/aapt2` / Termux `$PREFIX/bin/aapt2` when unset.

### Tests

```bash
./gradlew test
```

## Install (debug)

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Releases (GitHub Actions)

Push a tag `v*.*.*` (or run **Release** workflow with a tag input) to publish signed per-ABI APKs:

- `onionvpn-<version>-arm64-v8a.apk`
- `onionvpn-<version>-x86_64.apk`
- `SHA256SUMS.txt`

**Obtainium / sideload:** on Pixel and most phones use the **`arm64-v8a`** APK only.
`x86_64` is for emulators (`INSTALL_FAILED_NO_MATCHING_ABIS` on arm64 devices).
In Obtainium set an APK filter matching `arm64-v8a`. If install fails with
`INSTALL_FAILED_UPDATE_INCOMPATIBLE`, uninstall leftover installs on **all users/profiles**
(including work/test profiles) that used a different signing key, then retry.

### CI signing secrets

| Secret | Description |
|--------|-------------|
| `RELEASE_KEYSTORE_BASE64` | Base64-encoded `.jks` / `.keystore` |
| `RELEASE_KEYSTORE_PASSWORD` | Keystore password |
| `RELEASE_KEY_ALIAS` | Key alias (default in gradle: `onionvpn`) |
| `RELEASE_KEY_PASSWORD` | Key password (defaults to keystore password) |

Locally: copy `keystore.properties.example` → `keystore.properties` (gitignored).

## Native binaries

Prebuilt Tor / DNSCrypt and hev-socks5-tunnel live under `app/src/main/jniLibs/{arm64-v8a,x86_64}/`.
Refresh with `scripts/fetch-native-binaries.sh`:

- **Tor (C / little-t)** — [LTechnologies0/Tor-Android-build-script](https://github.com/LTechnologies0/Tor-Android-build-script)
  (our fork of Gedsh’s Android Tor build; GitHub Release `libtor-*.so`) — default engine
- **Arti (Rust)** — [arti-mobile](https://gitlab.com/guardianproject/tormobile/arti-mobile) Maven AAR
  (`org.torproject:arti-mobile`) ships `libarti_mobile_ex.so`; select **Arti** under Settings → Tor
- **DNSCrypt** — InviZible Lite **v7.5.0** APK extract
- **hev-socks5-tunnel** — sockstun APK extract

There is **no** runtime Tor binary OTA; ship updates by refreshing jniLibs / AAR and releasing a new OnionVPN APK.

### Tor engine (Settings → Tor)

Pick **C Tor** or **Arti** at runtime. Capabilities are gated via `TorEngineCapabilities`
(UI, validation, recovery, Automap).

| Capability | C Tor | Arti |
|------------|-------|------|
| SOCKS proxy | Multi-port SessionGroups | Single shared SOCKS (+ SOCKS user/pass) |
| `.onion` Automap | Native DNSPort Automap | App-side synthesizer → SOCKS5A |
| Classic ControlSocket | Yes | No (`arti.status` + Ext JNI / synthetic) |
| Circuits / streams UI | Yes | No (no list-circuits API) |
| ExitNodes country | StrictNodes | Single `{cc}` via `StreamPrefs::exit_country` (geoip) |
| Entry / ExcludeNodes | Yes | No |
| Conjure PT | Yes | Yes (`TransportConfig` + `libConjure.so`) |
| DORMANT / ACTIVE | SIGNAL | `TorClient::set_dormant` (patched SO) |
| MaxCircuitDirtiness | Live SETCONF | Ext JNI `reconfigure` (patched SO) |
| NewCircuitPeriod | Live SETCONF | `prediction_lifetime` analogue (patched SO) |
| RESOLVE | ControlPort | `TorClient::resolve` Ext JNI (DNSPort fallback) |
| New identity | SIGNAL NEWNYM | Runtime restart |
| Bridges + Lyrebird | Yes | Yes (managed path) |

OnionVPN ships a patched `libarti_mobile_ex.so` under `app/src/main/jniLibs/` (see
`native/arti-mobile-ex/`) that exports `ArtiControlNative` control-api≥2 on top of the
Maven AAR Java API. Rebuild with `./native/arti-mobile-ex/build-onionvpn.sh`.
Uses `[patch.crates-io]` → `third_party/arti-1.7.0-onionvpn` for SOCKS exit-country.

## Security / GrapheneOS

OnionVPN opts into hardware **memory tagging (MTE)** with `android:memtagMode="async"` on
`<application>` (same pattern as GrapheneOS Auditor / Camera). On MTE-capable devices the OS
enables tagging for the app process; on other devices the attribute is ignored.

**hardened_malloc** and **extended virtual address space (48-bit VA)** are GrapheneOS system
features, not something an APK can embed. For this 64-bit-only app they are **on by default** on
GrapheneOS. Do not disable *Native code memory tagging*, *Hardened malloc*, or *Extended virtual
address space* for OnionVPN unless you are debugging a confirmed native memory bug.

Coverage note: MTE applies most strongly to the JVM and JNI-loaded libraries (e.g. hev, arti).
Exec’d child processes (`libtor.so`, `libdnscrypt-proxy.so`, pluggable transports via
`ProcessBuilder`) run as separate processes under OS defaults. After enabling the tunnel on a
GrapheneOS Pixel 8+, check logcat for `SEGV_MTEAERR` or hardened_malloc fatal notifications:

```bash
adb logcat -d | grep -E 'SEGV_MTEAERR|hardened_malloc|memtag'
```

Local packaging check (no device):

```bash
./gradlew :app:processDebugMainManifest
./scripts/verify-memtag-manifest.sh
```

## License

Proprietary / OnionPhone family — see repository license when published.
