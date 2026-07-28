package ltechnologies.onionphone.onionvpn.core.vpn.firewall

/**
 * Process-wide hook so [ltechnologies.onionphone.onionvpn.core.vpn.forwarder.TunDnsMux]
 * can call the app-layer firewall without a reverse module dependency.
 *
 * Set from [ltechnologies.onionphone.onionvpn.OnionVpnApplication] to
 * [ltechnologies.onionphone.onionvpn.firewall.InteractiveFirewallEngine].
 */
object FirewallBridge {
    @Volatile
    var engine: PacketFirewall = PacketFirewall.AllowAll
}
