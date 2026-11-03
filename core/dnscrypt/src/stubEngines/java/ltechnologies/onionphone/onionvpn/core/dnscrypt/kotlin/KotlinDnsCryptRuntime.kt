package ltechnologies.onionphone.onionvpn.core.dnscrypt.kotlin

import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences

/**
 * Stub when the kotlin-DNSCrypt composite build is absent (CI / no sibling checkout).
 * Selecting [ltechnologies.onionphone.onionvpn.core.model.DnsEngine.KOTLIN] fails at start.
 */
internal class KotlinDnsCryptRuntime {
    var onLogLine: ((String) -> Unit)? = null

    suspend fun start(
        listenPort: Int,
        torSocksPort: Int,
        socksUser: String,
        serverName: String,
        preferences: TunnelPreferences,
    ) {
        throw UnsupportedOperationException(
            "kotlin-DNSCrypt composite build missing — place kotlin-DNSCrypt next to OnionVPN",
        )
    }

    suspend fun reconfigure(
        torSocksPort: Int,
        socksUser: String,
        serverName: String,
        preferences: TunnelPreferences,
    ) = Unit

    suspend fun clearQueryCache() = Unit

    fun isRunning(): Boolean = false

    fun stop() = Unit
}
