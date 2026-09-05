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
        val strippedAuth = stripEmbeddedAuthUserPass(profileText)
        val lines = strippedAuth
            .lineSequence()
            .map { it.trimEnd() }
            .filterNot { shouldStrip(it) }
            .map { forceRemoteTcp(it) }
            .toMutableList()

        // Force a single IPv4 TCP proto — OpenVPN last-wins; leftover `proto udp` after the
        // first rewritten line would still break Tor SOCKS (no UDP ASSOCIATE).
        lines.removeAll { it.trimStart().startsWith("proto ", ignoreCase = true) }
        lines.add(0, "proto tcp4-client")

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
            // Aggressive server ping-restart (often ~10s) fails under Tor RTT.
            // Keep a client ping; ignore pulled ping-restart via pull-filter below.
            "ping $PING_SEC",
            "ping-restart $PING_RESTART_SEC",
            "pull-filter ignore \"redirect-gateway\"",
            "pull-filter ignore \"dhcp-option DNS\"",
            "pull-filter ignore \"dhcp-option DOMAIN\"",
            "pull-filter ignore \"block-ipv6\"",
            "pull-filter ignore \"ping-restart\"",
            // VORACLE/CRIME: never negotiate link compression over Tor (even if pushed).
            "allow-compression no",
            "pull-filter ignore \"compress\"",
            "pull-filter ignore \"comp-lzo\"",
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
        // Many free .ovpn exports ship <ca> without remote-cert-tls → OpenVPN warns
        // and skips server-cert verification. Enable when a CA is present and no
        // other verify method is configured.
        if (profileHasCa(lines) && !profileHasServerCertVerify(lines)) {
            lines += "remote-cert-tls server"
            Timber.i("OpenVPN inject remote-cert-tls server (CA present, no verify method)")
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

    /** Credentials from OpenVPN INLINE FILE SUPPORT (`<auth-user-pass>`). */
    data class AuthUserPass(val username: String, val password: String)

    /**
     * Extract username/password only when the profile embeds them (OpenVPN man).
     *
     * ```
     * <auth-user-pass>
     * username
     * [password]   # optional
     * </auth-user-pass>
     * ```
     *
     * Standard forms that do **not** embed secrets (caller supplies via Settings /
     * management Auth): bare `auth-user-pass`, `auth-user-pass <path>`,
     * `auth-user-pass username-only`. Commented `#auth-user-pass` is ignored.
     * External credential files are not readable from a lone `.ovpn` import.
     */
    fun extractAuthUserPass(profileText: String): AuthUserPass? =
        extractInlineAuthUserPass(profileText)

    /**
     * True when an uncommented `auth-user-pass` directive is present (server may
     * require Auth via file, inline block, or management prompt).
     */
    fun hasActiveAuthUserPassDirective(profileText: String): Boolean {
        for (raw in profileText.lineSequence()) {
            val t = raw.trim()
            if (t.isEmpty() || t.startsWith("#") || t.startsWith(";")) continue
            if (t.equals("auth-user-pass", ignoreCase = true)) return true
            if (t.startsWith("auth-user-pass ", ignoreCase = true)) return true
        }
        return false
    }

    private fun extractInlineAuthUserPass(profileText: String): AuthUserPass? {
        val lines = profileText.lineSequence().map { it.trimEnd() }.toList()
        var i = 0
        while (i < lines.size) {
            if (!lines[i].trim().equals("<auth-user-pass>", ignoreCase = true)) {
                i++
                continue
            }
            i++
            val creds = ArrayList<String>(2)
            while (i < lines.size) {
                val body = lines[i].trim()
                if (body.equals("</auth-user-pass>", ignoreCase = true)) break
                if (body.isNotEmpty() && !body.startsWith("#") && !body.startsWith(";")) {
                    if (creds.size < 2) creds.add(body)
                }
                i++
            }
            return when {
                creds.isEmpty() -> null
                creds.size == 1 -> AuthUserPass(creds[0], "")
                else -> AuthUserPass(creds[0], creds[1])
            }
        }
        return null
    }

    /**
     * Remove inline `<auth-user-pass>…</auth-user-pass>` so rewrite() can inject our
     * managed auth-user-pass file / management Auth without duplicate credentials.
     */
    fun stripEmbeddedAuthUserPass(profileText: String): String {
        val out = ArrayList<String>()
        var skipping = false
        for (raw in profileText.lineSequence()) {
            val t = raw.trim()
            when {
                t.equals("<auth-user-pass>", ignoreCase = true) -> skipping = true
                t.equals("</auth-user-pass>", ignoreCase = true) -> skipping = false
                !skipping -> out.add(raw)
            }
        }
        return out.joinToString("\n").let { if (it.endsWith("\n") || it.isEmpty()) it else "$it\n" }
    }

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
        if (parts.size < 4) return
        val p = parts[3].lowercase()
        when {
            UDP_PROTO.containsMatchIn(parts[3]) -> parts[3] = "tcp"
            // Per-remote proto overrides global proto tcp4-client — force plain `tcp`.
            p == "tcp4" || p == "tcp6" || p == "tcp-client" ||
                p == "tcp4-client" || p == "tcp6-client" -> parts[3] = "tcp"
        }
    }

    fun writeTo(file: File, rewritten: String) {
        file.parentFile?.mkdirs()
        file.writeText(rewritten)
    }

    /** `remote host port udp|tcp6` → `remote host port tcp` (per-remote overrides global). */
    private fun forceRemoteTcp(line: String): String {
        val t = line.trim()
        if (!t.startsWith("remote ", ignoreCase = true)) return line
        val parts = t.split(Regex("\\s+")).toMutableList()
        if (parts.size < 4) return line
        val before = parts[3]
        forceRemoteProtoTcp(parts)
        return if (parts[3] != before) parts.joinToString(" ") else line
    }

    /** True when rewritten lines still include a CA (`<ca>` block, `ca `, or `capath`). */
    internal fun profileHasCa(lines: List<String>): Boolean {
        var inCa = false
        for (raw in lines) {
            val t = raw.trim()
            if (t.equals("<ca>", ignoreCase = true)) {
                inCa = true
                continue
            }
            if (inCa) {
                if (t.equals("</ca>", ignoreCase = true)) return true
                if (t.isNotEmpty() && !t.startsWith("#") && !t.startsWith(";")) return true
                continue
            }
            val lower = t.lowercase()
            if (lower.startsWith("ca ") || lower.startsWith("capath ")) return true
        }
        return false
    }

    /**
     * True when a server-certificate verification method is already configured
     * (after script `tls-verify` strip — those are not kept).
     */
    internal fun profileHasServerCertVerify(lines: List<String>): Boolean {
        for (raw in lines) {
            val lower = raw.trim().lowercase()
            if (lower.startsWith("remote-cert-tls") ||
                lower.startsWith("verify-x509-name") ||
                lower.startsWith("peer-fingerprint") ||
                lower.startsWith("verify-hash")
            ) {
                return true
            }
        }
        return false
    }

    /**
     * Fail-closed MitM gate: profile must ship a CA (`<ca>` / `ca` / `capath`) **or**
     * explicit peer pinning (`peer-fingerprint` / `verify-x509-name` / `verify-hash`).
     * `remote-cert-tls` alone is not enough without a CA to verify against.
     */
    fun hasServerTrustMaterial(profileText: String): Boolean {
        val lines = profileText.lineSequence().map { it.trimEnd() }.toList()
        if (profileHasCa(lines)) return true
        for (raw in lines) {
            val lower = raw.trim().lowercase()
            if (lower.startsWith("peer-fingerprint") ||
                lower.startsWith("verify-x509-name") ||
                lower.startsWith("verify-hash")
            ) {
                return true
            }
        }
        return false
    }

    const val NO_SERVER_TRUST_DETAIL =
        "OpenVPN profile needs a CA (<ca>/ca/capath) or peer-fingerprint / " +
            "verify-x509-name / verify-hash — refuse MitM-friendly imports"

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
            // Compression = VORACLE/CRIME oracle on nested TLS over Tor.
            lower.startsWith("comp-lzo") ||
            lower.startsWith("compress") ||
            lower.startsWith("allow-compression") ||
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
    /** Cap soft-restart storms (socks-error / TCP reset over Tor). */
    private const val CONNECT_RETRY_MAX = 12
    /** TLS control-channel handshake window for high Tor RTT. */
    private const val HAND_WINDOW_SEC = 120
    /**
     * Inner TCP MSS under VpnService MTU + OpenVPN + Tor overhead.
     * Nested TCP-over-Tor needs headroom so TLS ClientHello fits without fragmentation.
     */
    private const val MSSFIX = 800
    /**
     * Keepalive interval: Tor RTT (~1–3s) needs a short client ping so peers with
     * ~10s timeouts do not RST the control channel.
     */
    private const val PING_SEC = 3
    /** Ignore pulled ping-restart; Tor RTT spikes need more headroom than ~10s. */
    private const val PING_RESTART_SEC = 180
}
