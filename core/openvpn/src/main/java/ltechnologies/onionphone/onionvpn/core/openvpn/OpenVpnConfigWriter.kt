package ltechnologies.onionphone.onionvpn.core.openvpn

import java.io.File
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.observability.OpTrace
import timber.log.Timber

/**
 * Rewrites a user `.ovpn` so the OpenVPN control channel is forced through Tor SOCKS5
 * (TCP) and DNS/gateway push cannot fight OnionVPN's TUN / DNSCrypt path.
 *
 * Management uses a **filesystem unix socket** + `management-client` (ics-openvpn /
 * TARGET_ANDROID): OpenVPN connects to our [OpenVpnAndroidManagement] server for
 * NEED-OK / OPENTUN / PROTECTFD.
 */
object OpenVpnConfigWriter {
    private val UDP_PROTO = Regex("""\b(udp|udp4|udp6)\b""", RegexOption.IGNORE_CASE)

    /**
     * @param profileText raw imported `.ovpn` (preferably with `remote` already an IP)
     * @param socksPort Tor SessionGroup OPENVPN SocksPort
     * @param managementSockPath absolute path for unix management socket (server we bind)
     * @param socksAuthFile unused on socks-proxy line (OpenVPN 2.7 VER=5 bug); still
     *   written with IsolateSOCKSAuth tokens for probes / future shim
     */
    fun rewrite(
        profileText: String,
        socksPort: Int,
        managementSockPath: String,
        socksAuthFile: File? = null,
        /** OpenVPN auth-user-pass file (username\\npassword\\n); omit if unused. */
        authUserPassFile: File? = null,
        tunDevName: String = "tun",
        /** @deprecated TCP management port — ignored; unix socket is required for OPENTUN. */
        managementPort: Int = 0,
    ): String {
        val lines = profileText
            .lineSequence()
            .map { it.trimEnd() }
            .filterNot { shouldStrip(it) }
            .map { forceRemoteTcp(it) }
            .toMutableList()

        // Force IPv4 TCP — Tor SOCKS has no UDP ASSOCIATE (socks-extensions);
        // tcp4 avoids Happy-Eyeballs IPv6 CONNECT on the OPENVPN SessionGroup.
        if (lines.none { it.trimStart().startsWith("proto ", ignoreCase = true) }) {
            lines.add(0, "proto tcp4-client")
        } else {
            val idx = lines.indexOfFirst { it.trimStart().startsWith("proto ", ignoreCase = true) }
            lines[idx] = "proto tcp4-client"
        }

        // OpenVPN 2.7 (ics-openvpn / F-Droid ≥ Jan 2026) checks RFC1929 auth reply as
        // VER==5 (socks.c). Spec + Tor/Arti send VER==1 → false "server refused".
        // Do **not** pass socks-proxy authfile until upstream expects VER=1.
        // Isolation stays via dedicated OPENVPN SessionGroup SocksPort; Java
        // pinRemoteViaTor / probeSocksAuth still use IsolateSOCKSAuth tokens.
        if (socksAuthFile != null) {
            socksAuthFile.writeText(
                "${TunnelEndpoints.SOCKS_OPENVPN_USER}\n${TunnelEndpoints.SOCKS_OPENVPN_PASS}\n",
            )
        }
        val socksLine = "socks-proxy ${TunnelEndpoints.LOOPBACK} $socksPort"

        // Tor-stable control/data plane:
        // - socks-extensions: TCP CONNECT (no OpenVPN authfile — see VER bug above)
        // - path-spec / prop 368: KeepAliveIsolateSOCKSAuth on OPENVPN SocksPort
        // - SocksTimeout 120s → server-poll-timeout / hand-window
        // - pinRemoteViaTor uses SOCKS RESOLVE then CONNECT-by-IP (no clearnet DNS)
        // - socks-proxy-retry removed (ignored since OpenVPN 2.4)
        lines += listOf(
            socksLine,
            "nobind",
            "server-poll-timeout $SERVER_POLL_TIMEOUT_SEC",
            "connect-retry $CONNECT_RETRY_SEC $CONNECT_RETRY_MAX_WAIT_SEC",
            "connect-retry-max $CONNECT_RETRY_MAX",
            "hand-window $HAND_WINDOW_SEC",
            "resolv-retry 0",
            "auth-retry none",
            "persist-remote-ip",
            "tun-mtu ${TunnelEndpoints.VPN_MTU}",
            // Inner TCP MSS clamp (VpnService MTU); outer path is TCP-over-Tor.
            "mssfix $MSSFIX",
            // SoftEther/VPN Gate often pushes ping 3 + ping-restart 10. Ignoring all
            // "ping*" left us at ping 20 — server RSTs ~10s (STATE connection-reset).
            // Accept pulled ping interval; only ignore aggressive ping-restart.
            "ping $PING_SEC",
            "ping-restart $PING_RESTART_SEC",
            "pull-filter ignore \"redirect-gateway\"",
            "pull-filter ignore \"dhcp-option DNS\"",
            "pull-filter ignore \"dhcp-option DOMAIN\"",
            "pull-filter ignore \"block-ipv6\"",
            "pull-filter ignore \"ping-restart\"",
            "route-nopull",
            "persist-tun",
            "persist-key",
            // ics-openvpn: OpenVPN is management-client; UI owns the unix server + OPENTUN FD.
            // management-query-passwords: Auth via management (Android has no console TTY).
            "management $managementSockPath unix",
            "management-client",
            "management-hold",
            "management-query-passwords",
            "dev-type tun",
            "dev $tunDevName",
            // No external scripts / plugins (deterministic, no clearnet hooks).
            "script-security 0",
            "verb 3",
        )
        if (authUserPassFile != null) {
            lines += "auth-user-pass ${authUserPassFile.absolutePath}"
        }
        val out = lines.joinToString("\n") + "\n"
        Timber.i(
            "OpenVPN config rewritten socks=:%d mgmt=%s authUserPass=%s lines=%d bytes=%d",
            socksPort,
            managementSockPath.substringAfterLast('/'),
            authUserPassFile != null,
            lines.size,
            out.length,
        )
        OpTrace.info("openvpn", "config rewritten socks=:$socksPort lines=${lines.size}")
        return out
    }

    /**
     * True when the profile only offers UDP remotes / proto (cannot traverse Tor SOCKS).
     * After [rewrite] we force TCP, but a UDP-only server will never answer.
     */
    fun looksUdpOnly(profileText: String): Boolean {
        var globalUdp = false
        var globalTcp = false
        var tcpRemote = false
        var udpRemote = false
        var bareRemote = false
        for (raw in profileText.lineSequence()) {
            val t = raw.trim()
            if (t.isEmpty() || t.startsWith("#") || t.startsWith(";")) continue
            when {
                t.startsWith("proto ", ignoreCase = true) -> {
                    val p = t.substringAfter(' ').trim().lowercase()
                    when {
                        p.startsWith("udp") -> globalUdp = true
                        p.startsWith("tcp") -> globalTcp = true
                    }
                }
                t.startsWith("remote ", ignoreCase = true) -> {
                    val parts = t.split(Regex("\\s+"))
                    val proto = parts.getOrNull(3)?.lowercase()
                    when {
                        proto == null -> bareRemote = true
                        proto.startsWith("tcp") -> tcpRemote = true
                        proto.startsWith("udp") -> udpRemote = true
                        else -> bareRemote = true
                    }
                }
            }
        }
        if (tcpRemote || globalTcp) return false
        if (udpRemote && !bareRemote) return true
        return globalUdp && !globalTcp
    }

    /**
     * SoftEther / VPN Gate exports mention PacketiX / SoftEther / opengw.net.
     * Anonymous VPN Gate accounts use username/password `vpn` / `vpn`.
     */
    fun looksSoftEtherVpnGate(profileText: String): Boolean {
        val lower = profileText.lowercase()
        return lower.contains("softether") ||
            lower.contains("packetix") ||
            lower.contains("opengw") ||
            lower.contains("vpngate") ||
            lower.contains("virtual hub") ||
            lower.contains("secure nat")
    }

    /** VPN Gate anonymous account (SoftEther SecureNAT). */
    const val SOFTETHER_DEFAULT_USER = "vpn"
    const val SOFTETHER_DEFAULT_PASSWORD = "vpn"

    /**
     * Rewrite every `remote` whose host equals [fromHost] (case-insensitive) to [ipv4],
     * and force the optional proto token to `tcp`.
     */
    fun pinRemoteHostToIpv4(profileText: String, fromHost: String, ipv4: String): String {
        require(TunnelEndpoints.parseIpv4Literal(ipv4) != null) { "not an IPv4: $ipv4" }
        return profileText.lineSequence().joinToString("\n") { line ->
            val t = line.trim()
            if (!t.startsWith("remote ", ignoreCase = true)) return@joinToString line
            val parts = t.split(Regex("\\s+")).toMutableList()
            if (parts.size < 2) return@joinToString line
            if (!parts[1].equals(fromHost, ignoreCase = true)) return@joinToString line
            parts[1] = ipv4
            forceRemoteProtoTcp(parts)
            parts.joinToString(" ")
        } + "\n"
    }

    /**
     * Rewrite **every** `remote` host to the same [ipv4] (legacy single-server pin).
     * Prefer [pinRemoteHostToIpv4] per hostname for multi-remote profiles.
     */
    fun pinRemoteToIpv4(profileText: String, ipv4: String): String {
        require(TunnelEndpoints.parseIpv4Literal(ipv4) != null) { "not an IPv4: $ipv4" }
        return profileText.lineSequence().joinToString("\n") { line ->
            val t = line.trim()
            if (!t.startsWith("remote ", ignoreCase = true)) return@joinToString line
            val parts = t.split(Regex("\\s+")).toMutableList()
            if (parts.size < 2) return@joinToString line
            parts[1] = ipv4
            forceRemoteProtoTcp(parts)
            parts.joinToString(" ")
        } + "\n"
    }

    /** Distinct `remote` hosts (order preserved). */
    fun allRemoteHosts(profileText: String): List<String> {
        val out = LinkedHashSet<String>()
        for (raw in profileText.lineSequence()) {
            val t = raw.trim()
            if (!t.startsWith("remote ", ignoreCase = true)) continue
            if (t.startsWith("#") || t.startsWith(";")) continue
            val parts = t.split(Regex("\\s+"))
            if (parts.size >= 2) out.add(parts[1])
        }
        return out.toList()
    }

    /** First `remote` hostname/IP from a profile, or null. */
    fun firstRemoteHost(profileText: String): String? = allRemoteHosts(profileText).firstOrNull()

    private fun forceRemoteProtoTcp(parts: MutableList<String>) {
        if (parts.size >= 4 && UDP_PROTO.containsMatchIn(parts[3])) {
            parts[3] = "tcp"
        } else if (parts.size >= 4 && parts[3].equals("tcp4", true)) {
            parts[3] = "tcp"
        }
    }

    fun writeTo(file: File, rewritten: String) {
        file.parentFile?.mkdirs()
        file.writeText(rewritten)
    }

    /** `remote host port udp` → `remote host port tcp` (OpenVPN per-remote proto overrides global). */
    private fun forceRemoteTcp(line: String): String {
        val t = line.trim()
        if (!t.startsWith("remote ", ignoreCase = true)) return line
        val parts = t.split(Regex("\\s+")).toMutableList()
        if (parts.size >= 4 && UDP_PROTO.containsMatchIn(parts[3])) {
            parts[3] = "tcp"
            return parts.joinToString(" ")
        }
        return line
    }

    private fun shouldStrip(line: String): Boolean {
        val t = line.trim()
        if (t.isEmpty() || t.startsWith("#") || t.startsWith(";")) return false
        val lower = t.lowercase()
        return lower.startsWith("socks-proxy ") ||
            lower == "socks-proxy-retry" ||
            lower.startsWith("http-proxy ") ||
            lower.startsWith("management ") ||
            lower.startsWith("management-client") ||
            lower.startsWith("management-hold") ||
            lower.startsWith("management-query-passwords") ||
            lower.startsWith("route-nopull") ||
            lower.startsWith("redirect-gateway") ||
            lower.startsWith("pull-filter ") ||
            lower.startsWith("auth-user-pass") ||
            lower.startsWith("dev ") ||
            lower.startsWith("dev-type ") ||
            // Replace with Tor-tuned values (see rewrite())
            lower.startsWith("server-poll-timeout") ||
            lower.startsWith("connect-timeout") ||
            lower.startsWith("connect-retry") ||
            lower.startsWith("hand-window") ||
            lower.startsWith("tun-mtu") ||
            lower.startsWith("link-mtu") ||
            lower.startsWith("mssfix") ||
            lower.startsWith("fragment") ||
            lower.startsWith("ping ") ||
            lower.startsWith("ping-restart") ||
            lower.startsWith("keepalive") ||
            lower == "nobind" ||
            lower.startsWith("resolv-retry") ||
            lower.startsWith("auth-retry") ||
            lower.startsWith("persist-remote-ip") ||
            // UDP-only / Windows / conflict with Tor SOCKS path
            lower.startsWith("explicit-exit-notify") ||
            lower.startsWith("block-outside-dns") ||
            lower.startsWith("setenv opt block-outside-dns") ||
            lower.startsWith("dhcp-option dns") ||
            lower.startsWith("dhcp-option domain") ||
            lower.startsWith("script-security") ||
            lower.startsWith("verb ") ||
            lower == "daemon" ||
            lower.startsWith("log ") ||
            lower.startsWith("log-append") ||
            lower.startsWith("status ") ||
            lower.startsWith("writepid") ||
            lower.startsWith("plugin ") ||
            lower.startsWith("up ") ||
            lower.startsWith("down ") ||
            lower.startsWith("route-up ") ||
            lower.startsWith("route-pre-down ") ||
            lower.startsWith("ipchange ") ||
            lower.startsWith("learn-address ") ||
            lower.startsWith("client-connect ") ||
            lower.startsWith("client-disconnect ") ||
            lower.startsWith("tls-verify ") ||
            lower.startsWith("auth-user-pass-verify ")
    }

    /** Align with Tor SocksTimeout (AL-042); covers SOCKS CONNECT + TCP dial. */
    private const val SERVER_POLL_TIMEOUT_SEC = 120
    /** Base seconds between TCP reconnects; second arg caps exponential backoff. */
    private const val CONNECT_RETRY_SEC = 10
    private const val CONNECT_RETRY_MAX_WAIT_SEC = 120
    /** Cap soft-restart storms (socks-error / TCP reset over Tor). SoftEther/VPN Gate needs headroom. */
    private const val CONNECT_RETRY_MAX = 12
    /** TLS control-channel handshake window for high Tor RTT. */
    private const val HAND_WINDOW_SEC = 120
    /**
     * Inner TCP MSS under VpnService MTU + OpenVPN + Tor overhead.
     * SoftEther path is TCP-over-Tor already; keep headroom so TLS ClientHello
     * fits without SoftEther SecureNAT fragmentation/RST.
     */
    private const val MSSFIX = 800
    /**
     * SoftEther peer timeout is often ~10s. Send client ping ≤3s so Tor RTT (~1–3s)
     * still lands inside the server’s window (server-side ping-restart is not pull-filterable).
     */
    private const val PING_SEC = 3
    /** Ignore pulled ping-restart; Tor RTT spikes need headroom beyond SoftEther’s 10s. */
    private const val PING_RESTART_SEC = 180
}
