package ltechnologies.onionphone.onionvpn.core.model

/**
 * User-facing DNSCrypt features — both engines implement the same policy via different
 * secure backends (native `.so` vs org.kotlindnscrypt).
 */
data class DnsEngineCapabilities(
    val forceTcpOverTor: Boolean,
    val dnsCryptProtocolPadding: Boolean,
    val blockedNamesList: Boolean,
    val resolverCatalogFilters: Boolean,
    val anonymizedRelays: Boolean,
    val multiResolverSelection: Boolean,
    val autoResolverFailover: Boolean,
    val queryCache: Boolean,
    val cacheClearOnNewnym: Boolean,
    val noEdnsClientSubnet: Boolean,
    val ipv4AnswersOnly: Boolean,
    val ephemeralKeys: Boolean,
    val runtimeConfigForValidation: Boolean,
) {
    companion object {
        /** dnscrypt-proxy.toml + native process. */
        val NATIVE_PROXY = DnsEngineCapabilities(
            forceTcpOverTor = true,
            dnsCryptProtocolPadding = true,
            blockedNamesList = true,
            resolverCatalogFilters = true,
            anonymizedRelays = true,
            multiResolverSelection = true,
            autoResolverFailover = true,
            queryCache = true,
            cacheClearOnNewnym = true,
            noEdnsClientSubnet = true,
            ipv4AnswersOnly = true,
            ephemeralKeys = true,
            runtimeConfigForValidation = true,
        )

        /** JVM stub — equivalent privacy posture (padding always on in library). */
        val KOTLIN = NATIVE_PROXY.copy(
            runtimeConfigForValidation = true,
        )
    }
}

val DnsEngine.capabilities: DnsEngineCapabilities
    get() = when (this) {
        DnsEngine.NATIVE_PROXY -> DnsEngineCapabilities.NATIVE_PROXY
        DnsEngine.KOTLIN -> DnsEngineCapabilities.KOTLIN
    }
