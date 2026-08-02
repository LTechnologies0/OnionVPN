package ltechnologies.onionphone.onionvpn.core.vpn.onionmasq

/**
 * Decision helpers for onionmasq JNI calls that abort the process when mis-ordered.
 *
 * Upstream `libonionmasq_mobile.so` uses `panic = "abort"`. Several JNI entry points
 * call `OnionmasqMobile::get()`, which `expect()`s that `OnionMasqJni.init()` has
 * already succeeded. [kotlin.Result]/`runCatching` cannot catch SIGABRT.
 *
 * Tombstone (0.3.46 / versionCode 53): `startForwarder` → `stop` →
 * `OnionMasqJni.isRunning` → `unwrap_failed` → SIGABRT, because `start()` called
 * `stop()` before `OnionMasq.init()`.
 *
 * Blind spots hardened in 0.3.48: refreshCircuits*, getBytes*ForApp, setCountryCode,
 * setExcludedUids, setInternetConnectivity — all require init; Java API + call sites
 * must gate before JNI (native patch covers future .so rebuilds).
 */
object OnionmasqNativeGate {
    /**
     * Native [org.torproject.onionmasq.OnionMasq.stop] / `closeProxy` may only run
     * after we have handed a TUN fd to [org.torproject.onionmasq.OnionMasq.start]
     * on this forwarder instance (`proxyOwned`).
     */
    fun mayStopNativeProxy(proxyOwned: Boolean): Boolean = proxyOwned

    /**
     * Native [org.torproject.onionmasq.OnionMasq.isRunning] requires Java/native init.
     * Prefer Kotlin ownership flags over probing JNI before init.
     */
    fun mayProbeNativeRunning(javaInitialized: Boolean): Boolean = javaInitialized

    /**
     * Commands that need a live control channel (`refreshCircuits*`, live exit apply).
     * Requires both Java init and a running proxy.
     */
    fun mayCommandRunningProxy(javaInitialized: Boolean, nativeRunning: Boolean): Boolean =
        javaInitialized && nativeRunning

    /**
     * Read-only probes that need the singleton (`getBytes*ForApp`) but not a live proxy.
     */
    fun mayReadAppCounters(javaInitialized: Boolean): Boolean = javaInitialized
}
