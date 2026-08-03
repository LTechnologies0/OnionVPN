package ltechnologies.onionphone.onionvpn.core.dnscrypt.config

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences

/**
 * Package `config` — dnscrypt-proxy.toml + blocked-names generation (no process I/O).
 *
 * Imported by [ltechnologies.onionphone.onionvpn.core.dnscrypt.DnsCryptProcessManager]
 * (pipeline step 2: write config) and validation tests.
 */

/**
 * Builds OnionVPN DNSCrypt-proxy config: Tor SOCKS upstream, Tor DNSPort bootstrap,
 * MITM / captive hardening, public-resolvers source list.
 *
 * @see <a href="https://dnscrypt.info/">DNSCrypt</a>
 */
object DnsCryptConfigWriter {
    /** Basename of the blocked_names list written beside the TOML. */
    const val BLOCKED_NAMES_FILE = "blocked-names.txt"

    /**
     * IPv4 public resolvers (name → first stamp). Prefer [DnsCryptPublicResolvers] for metadata.
     */
    val knownServers: Map<String, String>
        get() = DnsCryptPublicResolvers.knownServers

    /**
     * Hostnames blocked to reduce DoH/DoT/captive side-channels over tunnel DNS.
     *
     * Do **not** block Google Play / FCM API hosts (`android.googleapis.com`,
     * `play.googleapis.com`, `mtalk.google.com`, …) — Signal, Twitter/X, and most
     * Android apps need them for push and API. Captive-portal probes only.
     */
    fun blockedNamesFileContent(): String = """
        ####################
        # Public DoH / DoT #
        ####################
        dns.google
        dns.google.com
        dns.cloudflare.com
        cloudflare-dns.com
        one.one.one.one
        mozilla.cloudflare-dns.com
        security.cloudflare-dns.com
        chrome.cloudflare-dns.com
        dns.quad9.net
        dns9.quad9.net
        dns10.quad9.net
        dns11.quad9.net
        doh.opendns.com
        doh.dns.sb
        dns.adguard.com
        dns-family.adguard.com
        dns.nextdns.io
        ####################
        # Captive portals  #
        ####################
        connectivitycheck.gstatic.com
        connectivitycheck.android.com
        captive.apple.com
        www.msftconnecttest.com
        msftncsi.com
        www.msftncsi.com
        detectportal.firefox.com
        network-test.debian.org
        neverssl.com
    """.trimIndent() + "\n"

    /**
     * @param configDirectory absolute dir for relative blocked_names_file / source cache
     * @param serverName public-resolvers name, legacy alias, or [DnsCryptPublicResolvers.AUTO]
     * @param listenPort loopback stub listener
     * @param torSocksPort DNSCrypt-dedicated Tor SocksPort (arti-mobile SessionGroup, C Tor,
     *   or onionmasq SOCKS sidecar when that plane is active)
     * @param torDnsPort Tor DNSPort for bootstrap/netprobe only
     */
    fun write(
        configDirectory: String,
        serverName: String = "cloudflare",
        listenPort: Int = TunnelEndpoints.DNSCRYPT_LISTEN_PORT,
        torSocksPort: Int = TunnelEndpoints.TOR_SOCKS_PORT,
        torDnsPort: Int = TunnelEndpoints.TOR_DNS_PORT,
        preferences: TunnelPreferences = TunnelPreferences(),
        /** SOCKS username → IsolationToken (onionmasq NEWNYM rotates via suffix). */
        socksUser: String = TunnelEndpoints.SOCKS_DNSCRYPT_USER,
    ): String {
        val bootstrap = "${TunnelEndpoints.LOOPBACK}:$torDnsPort"
        val user = socksUser.ifBlank { TunnelEndpoints.SOCKS_DNSCRYPT_USER }
        val proxy =
            "socks5://$user:${TunnelEndpoints.SOCKS_DNSCRYPT_PASS}" +
                "@${TunnelEndpoints.LOOPBACK}:$torSocksPort"
        val resolvedList = DnsCryptPublicResolvers.resolveNames(
            serverName.ifBlank { preferences.dnsCryptServerName },
        ).let { names ->
            val torFriendly = DnsCryptPublicResolvers.ensureTorFriendlyServers(names)
            if (!preferences.dnsCryptAnonymized) {
                torFriendly
            } else {
                // Prefer servers that document Anonymized DNSCrypt / relay compatibility.
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
        val isAuto = resolvedList.size == 1 && resolvedList[0] == DnsCryptPublicResolvers.AUTO
        val serverNamesBlock = if (isAuto) {
            "# server_names omitted — use every resolver matching require_* filters"
        } else {
            val quoted = resolvedList.joinToString(", ") { "'$it'" }
            "server_names = [$quoted]"
        }
        val staticBlock = if (isAuto) {
            ""
        } else {
            buildString {
                appendLine("[static]")
                for (name in resolvedList) {
                    appendLine("  [static.'$name']")
                    appendLine("    stamp = '${stampFor(name)}'")
                }
            }.trimEnd()
        }
        return """
            # Generated by OnionVPN — DNSCrypt upstream forced through Tor SOCKS
            # (C Tor SessionGroup / arti-mobile role mux / onionmasq sidecar).
            # MITM hardening: ephemeral keys, no TLS tickets, Tor-only bootstrap, blocked DoH/captive.
            listen_addresses = ['${TunnelEndpoints.LOOPBACK}:$listenPort']
            max_clients = 128
            ipv4_servers = true
            ipv6_servers = false
            # AAAA answers make apps Happy-Eyeballs onto IPv6 TUN (Signal/WhatsApp).
            # Tor exits + hev IPv6 are slower/flakier than IPv4 — force A-only.
            block_ipv6 = true
            dnscrypt_ephemeral_keys = true
            tls_disable_session_tickets = true
            tls_cipher_suite = [52393, 49199]

            require_dnssec = ${preferences.dnsCryptRequireDnssec}
            require_nolog = ${preferences.dnsCryptRequireNoLog}
            require_nofilter = ${preferences.dnsCryptRequireNoFilter}

            # Always TCP through Tor SOCKS — UDP ASSOCIATE is not a safe DNSCrypt-over-Tor path.
            force_tcp = true
            # DNSCrypt-over-Tor needs headroom; Tor SocksTimeout default is 120s.
            # Keep below TunDnsMux DNS_TIMEOUT so the mux can retry once.
            timeout = 45000
            keepalive = 30
            cert_refresh_delay = 240
            ${if (preferences.dnsCryptQueryPadding) {
                "# query_padding: DNSCrypt pads by protocol; prefer DoH padding if .so supports it"
            } else {
                "# query_padding disabled by preference (protocol may still pad)"
            }}
            ${if (preferences.dnsCryptBlockEcs) {
                "# block ECS: DNSCrypt stamps omit Client Subnet; DoH path must not leak ECS"
            } else {
                "# ECS block preference off"
            }}

            # Upstream DNSCrypt server connections go through Tor SOCKS (isolated port).
            proxy = '$proxy'

            # Bootstrap / netprobe hit loopback only (never system DNS):
            # - C Tor: Tor DNSPort (UDP+TCP) on this port
            # - Arti: TCP DNS adapter on this port (force_tcp) → TorClient::resolve /
            #   SOCKS RESOLVE / DoH :443; Arti stock dns-proxy may own UDP
            # - onionmasq: dual-stack SocksDnsBootstrapRelay → sidecar SOCKS RESOLVE + DoH
            bootstrap_resolvers = ['$bootstrap']
            ignore_system_dns = true
            netprobe_address = '$bootstrap'
            # dnscrypt-proxy units: seconds (upstream default 60). Cold Tor needs headroom.
            netprobe_timeout = 90

            # Local cache cuts repeat lookups over Tor (double-hop DNSCrypt path).
            # Flushed on Tor CLEARDNSCACHE/NEWNYM via DnsCryptProcessManager.clearQueryCache()
            # (soft restart — dnscrypt-proxy has no in-process cache flush API).
            cache = true
            cache_size = 512
            cache_min_ttl = 120
            cache_max_ttl = 1800
            cache_neg_min_ttl = 10
            cache_neg_max_ttl = 60

            $serverNamesBlock

            [blocked_names]
              blocked_names_file = '$BLOCKED_NAMES_FILE'

            [sources]
              [sources.'public-resolvers']
                urls = [
                  'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',
                  'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md',
                  'https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/public-resolvers.md',
                ]
                minisign_key = '${DnsCryptPublicResolvers.MINISIGN_KEY}'
                cache_file = '${DnsCryptPublicResolvers.SOURCE_CACHE_FILE}'
                refresh_delay = 72
                prefix = ''
${if (preferences.dnsCryptAnonymized) {
                """
              [sources.'relays']
                urls = [
                  'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md',
                  'https://download.dnscrypt.info/resolvers-list/v3/relays.md',
                  'https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/relays.md',
                ]
                minisign_key = '${DnsCryptPublicResolvers.MINISIGN_KEY}'
                cache_file = 'relays.md'
                refresh_delay = 72
                prefix = ''

            [anonymized_dns]
              skip_incompatible = true
              # Prefer any compatible relay; catalog filter prefers Anonymized-capable servers.
              routes = [
                { server_name='*', via=['*'] }
              ]
""".trimEnd()
            } else {
                ""
            }}

            $staticBlock
        """.trimIndent().replace(Regex("\n{3,}"), "\n\n") + "\n"
    }

    fun stampFor(serverName: String): String {
        val resolved = DnsCryptPublicResolvers.resolveName(serverName)
        if (resolved == DnsCryptPublicResolvers.AUTO) {
            return DnsCryptPublicResolvers.byName.getValue("cloudflare").stamps.first()
        }
        return DnsCryptPublicResolvers.byName[resolved]?.stamps?.first()
            ?: DnsCryptPublicResolvers.byName.getValue("cloudflare").stamps.first()
    }
}
