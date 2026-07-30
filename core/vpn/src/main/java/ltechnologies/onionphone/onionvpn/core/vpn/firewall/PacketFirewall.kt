package ltechnologies.onionphone.onionvpn.core.vpn.firewall

/**
 * Hot-path gate for outbound TUN packets / loopback SOCKS (PAC).
 * Implementations may block briefly while waiting for an interactive verdict.
 */
interface PacketFirewall {
    /**
     * @return true to forward the packet to hev/Tor; false to drop.
     */
    fun allowOutbound(packet: ByteArray, length: Int): Boolean

    /**
     * Gate for loopback SOCKS (PAC bridge) that never hits the TUN.
     * Default allow — interactive engine overrides.
     */
    fun allowSocksConnect(
        uid: Int,
        destHost: String,
        destIp: String,
        destPort: Int,
    ): Boolean = true

    companion object {
        val AllowAll: PacketFirewall = object : PacketFirewall {
            override fun allowOutbound(packet: ByteArray, length: Int): Boolean = true
        }
    }
}
