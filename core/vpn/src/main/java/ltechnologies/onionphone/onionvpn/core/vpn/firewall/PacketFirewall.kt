package ltechnologies.onionphone.onionvpn.core.vpn.firewall

/**
 * Hot-path gate for outbound TUN packets.
 * Implementations may block briefly while waiting for an interactive verdict.
 */
fun interface PacketFirewall {
    /**
     * @return true to forward the packet to hev/Tor; false to drop.
     */
    fun allowOutbound(packet: ByteArray, length: Int): Boolean

    companion object {
        val AllowAll: PacketFirewall = PacketFirewall { _, _ -> true }
    }
}
