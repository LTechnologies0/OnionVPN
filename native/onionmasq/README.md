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
   IsolationToken by SOCKS username (`dnscrypt` / `probe`). JNI:
   `OnionMasq.getSocksSidecarPort()`.
2. **Interim cold-start:** arti-mobile SOCKS + DNSPort until the orchestrator
   starts DNSCrypt after onionmasq is ready (`OnionmasqSocksSidecar.INTERIM_USES_ARTI_MOBILE`).

Re-apply OnionVPN patches after a clean onionmasq clone:

```bash
cd third_party/onionmasq
git apply ../../native/onionmasq/socks-sidecar.patch
git apply ../../native/onionmasq/safe-uninit-jni.patch
```

`safe-uninit-jni.patch` makes `isRunning` / `closeProxy` / `getSocksSidecarPort`
return safely when `init()` has not run (upstream `get().expect` + `panic=abort`
otherwise SIGABRTs the app). The Java/Kotlin layers also gate these calls; rebuild
the `.so` so the native side matches.
