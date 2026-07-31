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
| Tor engine | Dual backend: **C Tor** (`libtor.so`, default) or experimental **Arti** (Rust, `arti-mobile`) |

## Architecture

| Layer | Role |
|-------|------|
| Tor | SOCKS + DNSPort (ephemeral ports), SafeSocks depending on DNS mode |
| Arti (opt-in) | In-process Rust Tor via `org.torproject:arti-mobile`; one shared SOCKS + DNS; no classic ControlSocket |
| DNSCrypt | App DNS via TunDnsMux; upstream via Tor SOCKS; bootstrap via Tor DNSPort |
| VPN | `OnionVpnService` + hev-socks5-tunnel; client `10.8.0.2`, DNS `10.8.0.1` |
| Firewall | `InteractiveFirewallEngine` on the TUN; DNS hostname cache + local reputation DB (HaGeZi / URLhaus / Yoyo / uAssets) for prompt UI |

Modules: `app`, `core:model`, `core:tor`, `core:dnscrypt`, `core:vpn`, `core:validation`.

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

### Arti migration status

| Capability | C Tor | Arti |
|------------|-------|------|
| SOCKS proxy | Multi-port SessionGroups | Single shared SOCKS |
| DNSPort | Automap / VirtualAddr | DNS proxy port |
| Classic ControlSocket | Yes | No (synthetic bootstrap status) |
| Circuits UI / NEWNYM / live SETCONF | Yes | Not yet |
| Bridges + Lyrebird managed PT | Yes | Experimental (path-based) |
| Conjure | Yes | Not yet |

## License

Proprietary / OnionPhone family — see repository license when published.
