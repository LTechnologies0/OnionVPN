package ltechnologies.onionphone.onionvpn.core.dnscrypt.config

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.observability.OpTrace
import timber.log.Timber

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
        ####################
        # Onion / .exit    #
        # (TunDnsMux already routes these to Tor DNSPort / Automap — block if a
        #  clearnet query ever hits the DNSCrypt stub so exits never see .onion.)
        ####################
        *.onion
        *.exit
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
        socksUser: String = TunnelEndpoints.dnsCryptSocksUser(),
    ): String {
        val bootstrap = "${TunnelEndpoints.LOOPBACK}:$torDnsPort"
        val user = socksUser.ifBlank { TunnelEndpoints.dnsCryptSocksUser() }
        val proxy =
            "socks5://$user:${TunnelEndpoints.socksDnsCryptPass()}" +
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
        val toml = """
            # Generated by OnionVPN — DNSCrypt upstream forced through Tor SOCKS
            # (C Tor SessionGroup / arti-mobile role mux / onionmasq sidecar).
            # Spec: socks-extensions (no UDP ASSOCIATE) + path-spec stream isolation
            # (IsolateSOCKSAuth username) + dnscrypt-proxy Tor notes (force_tcp + proxy).
            # MITM hardening: ephemeral keys, no TLS tickets, Tor-only bootstrap, blocked DoH/captive.
            listen_addresses = ['${TunnelEndpoints.LOOPBACK}:$listenPort']
            max_clients = 128
            ipv4_servers = true
            ipv6_servers = false
            # AAAA answers make apps Happy-Eyeballs onto IPv6 TUN (Signal/WhatsApp).
            # Tor exits + hev IPv6 are slower/flakier than IPv4 — force A-only.
            block_ipv6 = true
            # Prefer classic DNSCrypt stamps over DoH (DoH = TLS to system CA).
            dnscrypt_servers = true
            doh_servers = false
            odoh_servers = false
            dnscrypt_ephemeral_keys = true
            tls_disable_session_tickets = true
            tls_cipher_suite = [52393, 49199]

            require_dnssec = ${preferences.dnsCryptRequireDnssec}
            require_nolog = ${preferences.dnsCryptRequireNoLog}
            require_nofilter = ${preferences.dnsCryptRequireNoFilter}

            # Always TCP through Tor SOCKS — UDP ASSOCIATE unsupported (socks-extensions).
            force_tcp = true
            # HTTP/3 = QUIC/UDP — impossible / leaky on Tor SOCKS; keep off explicitly.
            http3 = false
            http3_probe = false
            # Query wait (ms). Must stay < TunDnsMux DNS_TIMEOUT (25s) so mux can retry.
            # Upstream example caps ~10s as "reasonable"; Tor RTT needs more headroom.
            timeout = 20000
            # Do not shrink timeout under load — Tor latency already dominates.
            timeout_load_reduction = 0.0
            # Reuse DoH TCP on the KeepAliveIsolateSOCKSAuth circuit (path-spec / prop 368).
            keepalive = 60
            # Limit resolver fan-out: DNSCrypt SocksPort uses IsolateDest*; wp2+estimator
            # probes many peers → circuit storm. p2 + no estimator = Tor-stable.
            lb_strategy = 'p2'
            lb_estimator = false
            cert_refresh_delay = 240
            ${if (preferences.dnsCryptQueryPadding) {
                "# query_padding: DNSCrypt pads by protocol; prefer DoH padding if .so supports it"
            } else {
                "# query_padding disabled by preference (protocol may still pad)"
            }}
            ${if (preferences.dnsCryptBlockEcs) {
                "# block ECS: never set edns_client_subnet (would deanonymize over Tor exits)"
            } else {
                "# ECS block preference off"
            }}

            # Upstream DNSCrypt server connections go through Tor SOCKS (isolated port).
            # Username/password → IsolateSOCKSAuth token (socks-extensions stream isolation).
            proxy = '$proxy'

            # Bootstrap / netprobe hit loopback only (never system DNS):
            # - C Tor: Tor DNSPort (UDP+TCP) on this port
            # - Arti: TCP DNS adapter on this port (force_tcp) → TorClient::resolve /
            #   SOCKS RESOLVE / DoH :443; Arti stock dns-proxy may own UDP
            # - onionmasq: dual-stack SocksDnsBootstrapRelay → sidecar SOCKS RESOLVE + DoH
            bootstrap_resolvers = ['$bootstrap']
            ignore_system_dns = true
            netprobe_address = '$bootstrap'
            # dnscrypt-proxy units: seconds (upstream default 60). Cold Tor needs headroom ≤ SocksTimeout.
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
        Timber.i(
            "DNSCrypt config written listen=:%d socks=:%d servers=%s anonymized=%s bytes=%d",
            listenPort,
            torSocksPort,
            if (isAuto) "AUTO" else resolvedList.joinToString(","),
            preferences.dnsCryptAnonymized,
            toml.length,
        )
        OpTrace.info(
            "dnscrypt",
            "config written listen=:$listenPort servers=${if (isAuto) "AUTO" else resolvedList.size}",
        )
        return toml
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
