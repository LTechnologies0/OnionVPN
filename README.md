# OnionVPN

Tor + DNSCrypt VPN for Android (InviZible / Mullvad-inspired). Traffic is forced through Tor; app DNS goes through DNSCrypt over Tor SOCKS (default), with FakeDNS/SOCKS5A as a settings fallback.

**Package:** `ltechnologies.onionphone.onionvpn`  
**Min SDK 26 · Target / Compile SDK 37 · Java/Kotlin 21 · Jetpack Compose**

## Architecture

| Layer | Role |
|-------|------|
| Tor | SOCKS + DNSPort (ephemeral ports), SafeSocks depending on DNS mode |
| DNSCrypt | App DNS via TunDnsMux; upstream via Tor SOCKS; bootstrap via Tor DNSPort |
| VPN | `OnionVpnService` + hev-socks5-tunnel; client `10.8.0.2`, DNS `10.8.0.1` |

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

Prebuilt Tor / DNSCrypt (from InviZible Lite) and hev-socks5-tunnel (sockstun) live under `app/src/main/jniLibs/{arm64-v8a,x86_64}/`. Refresh with `scripts/fetch-native-binaries.sh`.

## License

Proprietary / OnionPhone family — see repository license when published.
