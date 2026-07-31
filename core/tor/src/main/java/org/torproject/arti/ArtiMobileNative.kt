package org.torproject.arti

/**
 * Same-package bridge to package-private [ArtiJNI].
 *
 * `ArtiProxy` always passes a null managed-PT path; OnionVPN needs to hand Arti the
 * absolute path to [libLyrebird.so] / [libobfs4proxy.so] for ClientTransportPlugin-style
 * managed PTs. Living in `org.torproject.arti` is intentional so we can call [ArtiJNI].
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
}
