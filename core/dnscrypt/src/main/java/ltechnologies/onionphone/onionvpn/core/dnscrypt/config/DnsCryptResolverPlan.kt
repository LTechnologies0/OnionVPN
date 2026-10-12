package ltechnologies.onionphone.onionvpn.core.dnscrypt.config

import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences

/**
 * Shared resolver selection for native dnscrypt-proxy and kotlin-DNSCrypt — same names,
 * Tor-friendly fallbacks, and anonymized catalog filtering.
 */
object DnsCryptResolverPlan {
    fun resolvedServerNames(
        serverName: String,
        preferences: TunnelPreferences,
    ): List<String> {
        val names = DnsCryptPublicResolvers.resolveNames(
            serverName.ifBlank { preferences.dnsCryptServerName },
        )
        return if (!preferences.dnsCryptAnonymized) {
            DnsCryptPublicResolvers.ensureTorFriendlyServers(names)
        } else {
            val torFriendly = DnsCryptPublicResolvers.ensureTorFriendlyServers(names)
            val filtered = torFriendly.filter { name ->
                if (name == DnsCryptPublicResolvers.AUTO) return@filter true
                val desc = DnsCryptPublicResolvers.byName[name]?.description.orEmpty()
                !desc.contains("incompatible with anonymization", ignoreCase = true) &&
                    (
                        desc.contains("Anonymized DNSCrypt", ignoreCase = true) ||
                            desc.contains("as Anonymized", ignoreCase = true) ||
                            desc.contains("relay", ignoreCase = true) ||
                            name.startsWith("dnscry.pt-")
                        )
            }
            filtered.ifEmpty { torFriendly }
        }
    }

    val isAutoSelection: (List<String>) -> Boolean = { list ->
        list.size == 1 && list[0] == DnsCryptPublicResolvers.AUTO
    }
}
