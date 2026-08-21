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
            .toMutableList()

        // Force TCP — UDP/1194 is blackholed on the OnionVPN TUN path.
        if (lines.none { it.startsWith("proto ", ignoreCase = true) }) {
            lines.add(0, "proto tcp-client")
        } else {
            val idx = lines.indexOfFirst { it.startsWith("proto ", ignoreCase = true) }
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
     * Rewrite every `remote host port …` so [host] is replaced by [ipv4] (Tor-resolved).
     * Avoids clearnet DNS of the VPN server before socks-proxy is used.
     */
    fun pinRemoteToIpv4(profileText: String, ipv4: String): String {
        require(TunnelEndpoints.parseIpv4Literal(ipv4) != null) { "not an IPv4: $ipv4" }
        return profileText.lineSequence().joinToString("\n") { line ->
            val t = line.trim()
            if (!t.startsWith("remote ", ignoreCase = true)) return@joinToString line
            val parts = t.split(Regex("\\s+"))
            if (parts.size < 2) return@joinToString line
            val rest = parts.drop(2).joinToString(" ")
            if (rest.isEmpty()) "remote $ipv4" else "remote $ipv4 $rest"
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
            lower.startsWith("dev-type ")
    }
}
