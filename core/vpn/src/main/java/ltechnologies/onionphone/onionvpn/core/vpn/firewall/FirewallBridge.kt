package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import java.net.Socket

/**
 * Process-wide hook so [ltechnologies.onionphone.onionvpn.core.vpn.forwarder.TunDnsMux]
 * and [ltechnologies.onionphone.onionvpn.core.vpn.pac.DnsCryptSocksBridge] /
 * [ltechnologies.onionphone.onionvpn.core.vpn.forwarder.SocksUidBridge] can call the
 * app-layer firewall without a reverse module dependency.
 *
 * Set from [ltechnologies.onionphone.onionvpn.OnionVpnApplication] to
 * [ltechnologies.onionphone.onionvpn.firewall.InteractiveFirewallEngine].
 */
object FirewallBridge {
    @Volatile
    var engine: PacketFirewall = PacketFirewall.AllowAll

    /**
     * Resolves the UID of a client connected to the PAC SOCKS bridge (loopback).
     * Set alongside [engine] so core:vpn does not need Android Context wiring.
     */
    @Volatile
    var resolveSocksClientUid: ((Socket) -> Int)? = null

    /**
     * Fired when Tor Automap reuses a virtual IP for a different `.onion` hostname.
     * Firewall must drop IP-keyed decisions so ALLOW/DENY cannot cross HS boundaries.
     */
    @Volatile
    var onAutomapRemap: ((ip: String, oldHost: String, newHost: String) -> Unit)? = null

    /**
     * When OpenVPN-over-Tor is up, TunDnsMux writes [FirewallVerdict.ALLOW_OVPN]
     * packets here (IP frames for the userspace OVPN tun). Null = OVPN down /
     * unavailable → OVPN routes fail-closed.
     */
    @Volatile
    var ovpnPacketSink: OvpnPacketSink? = null

    /** True when OVPN-over-Tor is connected and accepting ALLOW_OVPN traffic. */
    @Volatile
    var openVpnOverTorUp: Boolean = false

    /**
     * Optional callback to inject decrypted OVPN→app IP packets into the VpnService TUN
     * (set by TunDnsMux while the TUN is live).
     */
    @Volatile
    var injectToVpnTun: ((ByteArray, Int) -> Unit)? = null
}

/** Hot-path sink for ALLOW_OVPN IP packets (written instead of hev). */
fun interface OvpnPacketSink {
    /** @return true if the packet was accepted for OVPN encapsulation. */
    fun offer(packet: ByteArray, length: Int): Boolean
}
