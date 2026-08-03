# onionmasq native build (OnionVPN)

Tor Project [onionmasq](https://gitlab.torproject.org/tpo/core/onionmasq) provides
`libonionmasq_mobile.so` (TUN → smoltcp → arti-client).

## Build

```bash
# Clone once (or keep third_party/onionmasq symlink)
git clone --depth 1 https://gitlab.torproject.org/tpo/core/onionmasq.git third_party/onionmasq

export ANDROID_HOME=~/Android/Sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/27.3.13750724
./native/onionmasq/build-onionvpn.sh arm64-v8a
```

Copies `libonionmasq_mobile.so` into `app/src/main/jniLibs/<abi>/`.

Java API is vendored as Gradle module `:third_party:onionmasq-android`.

## DNSCrypt

App DNS still goes TunDnsMux → DNSCrypt. Upstream SOCKS:

1. **onionmasq SOCKS sidecar** (patched `onionmasq-mobile`) — same TorClient,
   IsolationToken by SOCKS username (`dnscrypt` / `dnscrypt-nN` / `probe`).
   Password allowlist matches `TunnelEndpoints` (`resolver` / `check`); auth
   failure returns RFC1929 status `0x01`. JNI: `OnionMasq.getSocksSidecarPort()`.
2. **Cutover (single TorClient):** DNSCrypt starts after onionmasq ready against
   the sidecar (`INTERIM_USES_ARTI_MOBILE = false`). Bootstrap DNS uses
   `SocksDnsBootstrapRelay` over the sidecar — no parallel arti-mobile.

Re-apply OnionVPN patches after a clean onionmasq clone:

```bash
cd third_party/onionmasq
git apply ../../native/onionmasq/socks-sidecar.patch
git apply ../../native/onionmasq/safe-uninit-jni.patch
```

`safe-uninit-jni.patch` converts **all** probe/stop/config/command JNI entry points
to `try_get()` (no-op / 0 / Java exception) when `init()` has not run. Upstream
`get().expect` + `panic=abort` otherwise SIGABRTs the app. Java/Kotlin layers also
gate these calls; rebuild the `.so` so the native side matches.
