package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import ltechnologies.onionphone.onionvpn.core.model.FirewallVerdict

/**
 * Which loopback SOCKS plane is asking for a CONNECT verdict.
 * Both must hit the interactive engine — never dial Tor SOCKS without a review.
 */
enum class SocksConnectPlane {
    /** hev → [SocksUidBridge] → Tor (TUN already gated SYN; CONNECT re-checks). */
    HEV_UID_BRIDGE,

    /** App PAC URL → [DnsCryptSocksBridge] (never hits TUN; sole gate). */
    PAC_DNSCRYPT_BRIDGE,
}

/**
 * Hot-path gate for outbound TUN packets / loopback SOCKS (PAC + hev bridge).
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
     * Gate for loopback SOCKS CONNECT (PAC bridge / hev UID bridge) that may not
     * hit the TUN packet path. Default allow via Tor — interactive engine overrides.
     */
    fun socksConnectRoute(
        uid: Int,
        destHost: String,
        destIp: String,
        destPort: Int,
        plane: SocksConnectPlane = SocksConnectPlane.PAC_DNSCRYPT_BRIDGE,
    ): FirewallVerdict = FirewallVerdict.ALLOW_TOR

    fun allowSocksConnect(
        uid: Int,
        destHost: String,
        destIp: String,
        destPort: Int,
        plane: SocksConnectPlane = SocksConnectPlane.PAC_DNSCRYPT_BRIDGE,
    ): Boolean = socksConnectRoute(uid, destHost, destIp, destPort, plane).forwards

    companion object {
        val AllowAll: PacketFirewall = object : PacketFirewall {
            override fun outboundRoute(packet: ByteArray, length: Int): FirewallVerdict =
                FirewallVerdict.ALLOW_TOR
        }
    }
}
