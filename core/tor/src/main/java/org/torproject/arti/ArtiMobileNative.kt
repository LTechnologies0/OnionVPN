package org.torproject.arti

/**
 * Same-package bridge to package-private [ArtiJNI] + optional [ArtiControlNative].
 *
 * `ArtiProxy` always passes a null managed-PT path; OnionVPN needs to hand Arti the
 * absolute path to [libLyrebird.so] / [libobfs4proxy.so] for ClientTransportPlugin-style
 * managed PTs. Living in `org.torproject.arti` is intentional so we can call [ArtiJNI].
 *
 * Control ops (dormant / max_dirtiness / bootstrap) go through [ArtiControlNative] when
 * the patched `libarti_mobile_ex.so` is present; otherwise callers use app-layer fallbacks.
 */
object ArtiMobileNative {
    fun start(
        cacheDir: String,
        stateDir: String,
        obfs4Port: Int,
        snowflakePort: Int,
        obfs4proxyPath: String?,
        bridgeLines: String?,
        socksPort: Int,
        dnsPort: Int,
        logListener: ArtiLogListener,
    ): String = ArtiJNI.startArtiProxyJNI(
        cacheDir,
        stateDir,
        obfs4Port,
        snowflakePort,
        obfs4proxyPath,
        bridgeLines,
        socksPort,
        dnsPort,
        logListener,
    )

    fun stop() {
        ArtiJNI.stopArtiProxyJNI()
    }

    /** True when OnionVPN Ext JNI (set_dormant / max_dirtiness / bootstrap) is linked. */
    fun hasControlApi(): Boolean = ArtiControlNative.isAvailable()
}
