package ltechnologies.onionphone.onionvpn.core.vpn.pac

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints

/**
 * PAC script for apps: points at the **DNSCrypt→Tor SOCKS bridge**, not raw Tor SOCKS.
 *
 * Raw Tor SOCKS/HTTPTunnel would resolve names via Tor DNSPort/exit DNS (Chrome/Edge
 * always do SOCKS remote DNS). The bridge resolves via DNSCrypt first, then CONNECT by IP.
 *
 * The PAC **URL** stays fixed; [bridgeSocksPort] is fixed ([TunnelEndpoints.PAC_BRIDGE_SOCKS_PORT]).
 */
object PacScript {
    fun build(
        bridgeSocksHost: String = TunnelEndpoints.LOOPBACK,
        bridgeSocksPort: Int = TunnelEndpoints.PAC_BRIDGE_SOCKS_PORT,
        failClosedWhenDown: Boolean = true,
        bridgeUp: Boolean = true,
    ): String {
        if (!bridgeUp || bridgeSocksPort <= 0) {
            return if (failClosedWhenDown) {
                """
                |// OnionVPN — tunnel / DNSCrypt bridge down (fail-closed)
                |function FindProxyForURL(url, host) {
                |  return "PROXY 127.0.0.1:1";
                |}
                """.trimMargin()
            } else {
                """
                |function FindProxyForURL(url, host) {
                |  return "DIRECT";
                |}
                """.trimMargin()
            }
        }

        val chain = "SOCKS5 $bridgeSocksHost:$bridgeSocksPort; SOCKS $bridgeSocksHost:$bridgeSocksPort"
        return """
            |// OnionVPN PAC — stable URL; SOCKS = DNSCrypt→Tor bridge (not Tor DNS).
            |// Name resolution: DNSCrypt stub → A record → Tor SocksPort CONNECT by IP.
            |// .onion / .exit: bridge passes hostname to Tor SOCKS5A (no DNSCrypt).
            |function FindProxyForURL(url, host) {
            |  // Host-only checks — no PAC dnsResolve (can leak / stall outside the VPN).
            |  if (isPlainHostName(host) ||
            |      shExpMatch(host, "localhost") ||
            |      shExpMatch(host, "127.*") ||
            |      shExpMatch(host, "10.*") ||
            |      shExpMatch(host, "192.168.*") ||
            |      shExpMatch(host, "172.16.*") ||
            |      shExpMatch(host, "172.17.*") ||
            |      shExpMatch(host, "172.18.*") ||
            |      shExpMatch(host, "172.19.*") ||
            |      shExpMatch(host, "172.2[0-9].*") ||
            |      shExpMatch(host, "172.3[01].*") ||
            |      shExpMatch(host, "*.local") ||
            |      shExpMatch(host, "*.onionvpn.local")) {
            |    return "DIRECT";
            |  }
            |  return "$chain";
            |}
            """.trimMargin()
    }
}
