package ltechnologies.onionphone.onionvpn.core.vpn.dns

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OnionAutomapRoutingTest {
    @Test
    fun automapVirtualPool_matchesTorVirtualAddrNetworkSlash10() {
        assertTrue(TunnelEndpoints.isAutomapVirtualIpv4("10.192.0.1"))
        assertTrue(TunnelEndpoints.isAutomapVirtualIpv4("10.255.255.255"))
        assertTrue(TunnelEndpoints.isAutomapVirtualIpv4("10.200.1.2"))
        assertFalse(TunnelEndpoints.isAutomapVirtualIpv4("10.191.255.255"))
        assertFalse(TunnelEndpoints.isAutomapVirtualIpv4("10.8.0.2"))
        assertFalse(TunnelEndpoints.isAutomapVirtualIpv4("100.64.0.1"))
        assertFalse(TunnelEndpoints.isAutomapVirtualIpv4("not-an-ip"))
    }

    @Test
    fun onionLikeHostnames_neverGoToDnsCrypt() {
        assertTrue(TunnelEndpoints.isOnionLikeHostname("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"))
        assertTrue(TunnelEndpoints.isOnionLikeHostname("example.onion."))
        assertTrue(TunnelEndpoints.isOnionLikeHostname("www.example.com.exit"))
        assertFalse(TunnelEndpoints.isOnionLikeHostname("example.com"))
        assertFalse(TunnelEndpoints.isOnionLikeHostname("onion.com"))
        assertFalse(TunnelEndpoints.isOnionLikeHostname(""))
    }

    @Test
    fun hostnameCache_mapsAutomapIpToOnionForSocks5a() {
        DnsHostnameCache.clear()
        DnsHostnameCache.put("10.192.0.42", "abc.onion")
        assertTrue(TunnelEndpoints.isOnionLikeHostname(DnsHostnameCache.lookup("10.192.0.42")!!))
        DnsHostnameCache.clear()
    }
}
