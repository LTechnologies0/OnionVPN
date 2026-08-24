package ltechnologies.onionphone.onionvpn.core.openvpn

import java.io.File
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints

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
     * @param socksAuthFile OpenVPN socks-proxy authfile (user\\npass\\n)
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

        // Force TCP — UDP is blackholed on the OnionVPN TUN / Tor SOCKS path.
        if (lines.none { it.trimStart().startsWith("proto ", ignoreCase = true) }) {
            lines.add(0, "proto tcp-client")
        } else {
            val idx = lines.indexOfFirst { it.trimStart().startsWith("proto ", ignoreCase = true) }
            lines[idx] = "proto tcp-client"
        }

        val socksLine = if (socksAuthFile != null) {
            socksAuthFile.writeText(
                "${TunnelEndpoints.SOCKS_OPENVPN_USER}\n${TunnelEndpoints.SOCKS_OPENVPN_PASS}\n",
            )
            "socks-proxy ${TunnelEndpoints.LOOPBACK} $socksPort ${socksAuthFile.absolutePath}"
        } else {
            "socks-proxy ${TunnelEndpoints.LOOPBACK} $socksPort"
        }

        lines += listOf(
            socksLine,
            "socks-proxy-retry",
            "pull-filter ignore \"redirect-gateway\"",
            "pull-filter ignore \"dhcp-option DNS\"",
            "pull-filter ignore \"dhcp-option DOMAIN\"",
            "pull-filter ignore \"block-ipv6\"",
            "route-nopull",
            "persist-tun",
            "persist-key",
            // ics-openvpn: OpenVPN is management-client; UI owns the unix server + OPENTUN FD.
            "management $managementSockPath unix",
            "management-client",
            "management-hold",
            "dev-type tun",
            "dev $tunDevName",
            "verb 3",
        )
        if (authUserPassFile != null) {
            lines += "auth-user-pass ${authUserPassFile.absolutePath}"
        }
        return lines.joinToString("\n") + "\n"
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
     * Rewrite every `remote host port …` so [host] is replaced by [ipv4] (Tor-resolved).
     * Avoids clearnet DNS of the VPN server before socks-proxy is used.
     * Forces the optional proto token to `tcp` (never leave `udp` on the remote line).
     */
    fun pinRemoteToIpv4(profileText: String, ipv4: String): String {
        require(TunnelEndpoints.parseIpv4Literal(ipv4) != null) { "not an IPv4: $ipv4" }
        return profileText.lineSequence().joinToString("\n") { line ->
            val t = line.trim()
            if (!t.startsWith("remote ", ignoreCase = true)) return@joinToString line
            val parts = t.split(Regex("\\s+")).toMutableList()
            if (parts.size < 2) return@joinToString line
            parts[1] = ipv4
            if (parts.size >= 4 && UDP_PROTO.containsMatchIn(parts[3])) {
                parts[3] = "tcp"
            } else if (parts.size >= 4 && parts[3].equals("tcp4", true)) {
                parts[3] = "tcp"
            }
            parts.joinToString(" ")
        } + "\n"
    }

    /** First `remote` hostname/IP from a profile, or null. */
    fun firstRemoteHost(profileText: String): String? {
        for (raw in profileText.lineSequence()) {
            val t = raw.trim()
            if (!t.startsWith("remote ", ignoreCase = true)) continue
            if (t.startsWith("#") || t.startsWith(";")) continue
            val parts = t.split(Regex("\\s+"))
            if (parts.size >= 2) return parts[1]
        }
        return null
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
            lower.startsWith("http-proxy ") ||
            lower.startsWith("management ") ||
            lower.startsWith("management-client") ||
            lower.startsWith("management-hold") ||
            lower.startsWith("route-nopull") ||
            lower.startsWith("redirect-gateway") ||
            lower.startsWith("pull-filter ") ||
            lower.startsWith("auth-user-pass") ||
            lower.startsWith("dev ") ||
            lower.startsWith("dev-type ") ||
            // UDP-only / Windows / conflict with Tor SOCKS path
            lower.startsWith("explicit-exit-notify") ||
            lower.startsWith("block-outside-dns") ||
            lower.startsWith("setenv opt block-outside-dns") ||
            lower.startsWith("dhcp-option dns") ||
            lower.startsWith("dhcp-option domain")
    }
}
