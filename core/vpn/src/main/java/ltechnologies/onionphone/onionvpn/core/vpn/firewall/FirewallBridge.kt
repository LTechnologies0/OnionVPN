package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import java.net.Socket

/**
 * Process-wide hook so [ltechnologies.onionphone.onionvpn.core.vpn.forwarder.TunDnsMux]
 * and [ltechnologies.onionphone.onionvpn.core.vpn.pac.DnsCryptSocksBridge] can call the
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
}
