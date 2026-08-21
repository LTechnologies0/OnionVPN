package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import ltechnologies.onionphone.onionvpn.core.model.FirewallVerdict

/**
 * Hot-path gate for outbound TUN packets / loopback SOCKS (PAC).
 * Implementations may block briefly while waiting for an interactive verdict.
 */
interface PacketFirewall {
    /**
     * Route an outbound TUN packet.
     * @return [FirewallVerdict.DENY] to drop; [ALLOW_TOR] / [ALLOW_OVPN] to forward.
     */
    fun outboundRoute(packet: ByteArray, length: Int): FirewallVerdict

    /**
     * @return true to forward (Tor or OVPN); false to drop.
     */
    fun allowOutbound(packet: ByteArray, length: Int): Boolean =
        outboundRoute(packet, length).forwards

    /**
     * Gate for loopback SOCKS (PAC bridge) that never hits the TUN.
     * Default allow via Tor — interactive engine overrides.
     */
    fun socksConnectRoute(
        uid: Int,
        destHost: String,
        destIp: String,
        destPort: Int,
    ): FirewallVerdict = FirewallVerdict.ALLOW_TOR

    fun allowSocksConnect(
        uid: Int,
        destHost: String,
        destIp: String,
        destPort: Int,
    ): Boolean = socksConnectRoute(uid, destHost, destIp, destPort).forwards

    companion object {
        val AllowAll: PacketFirewall = object : PacketFirewall {
            override fun outboundRoute(packet: ByteArray, length: Int): FirewallVerdict =
                FirewallVerdict.ALLOW_TOR
        }
    }
}
