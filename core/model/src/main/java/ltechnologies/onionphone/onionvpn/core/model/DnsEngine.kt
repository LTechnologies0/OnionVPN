package ltechnologies.onionphone.onionvpn.core.model

/**
 * DNSCrypt stub implementation for the tunnel.
 *
 * - [NATIVE_PROXY]: pinned `libdnscrypt-proxy.so` (dnscrypt-proxy feature set).
 * - [KOTLIN]: in-process stub using [org.kotlindnscrypt] over Tor SOCKS (forceTcp).
 */
enum class DnsEngine {
    NATIVE_PROXY,
    KOTLIN,
    ;

    val displayName: String
        get() = when (this) {
            NATIVE_PROXY -> "dnscrypt-proxy (native)"
            KOTLIN -> "kotlin-DNSCrypt (JVM)"
        }

    fun settingsSubtitle(): String {
        val c = capabilities
        return buildString {
            append(displayName)
            append(": ")
            append("DNSCrypt-over-Tor (force TCP). ")
            if (c.anonymizedRelays) append("Anonymized relays when enabled in prefs. ")
            if (c.dnsCryptProtocolPadding) append("Protocol padding on. ")
            append("No EDNS Client Subnet. IPv4-only answers. ")
            append("Blocked-names list. Resolver filters (no-log/DNSSEC/no-filter). ")
            if (c.queryCache) append("Query cache with flush on NEWNYM/CLEARDNSCACHE. ")
            if (c.autoResolverFailover) append("AUTO + multi-select failover. ")
            append("Same Settings knobs as the other engine.")
        }
    }

    companion object {
        fun fromPreference(raw: String?): DnsEngine =
            entries.firstOrNull { it.name.equals(raw, ignoreCase = true) } ?: NATIVE_PROXY
    }
}
