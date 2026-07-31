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

    @Test
    fun artiAutomapAllocator_stableVirtualIpInTorPool() {
        OnionAutomapAllocator.clear()
        DnsHostnameCache.clear()
        val a = OnionAutomapAllocator.ipv4ForHostname("abc.onion")
        val b = OnionAutomapAllocator.ipv4ForHostname("abc.onion")
        assertTrue(a == b)
        assertTrue(TunnelEndpoints.isAutomapVirtualIpv4(a))
        assertTrue(DnsHostnameCache.lookup(a) == "abc.onion")
        val dns = byteArrayOf(
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 'a'.code.toByte(), 'b'.code.toByte(), 'c'.code.toByte(),
            0x05, 'o'.code.toByte(), 'n'.code.toByte(), 'i'.code.toByte(),
            'o'.code.toByte(), 'n'.code.toByte(), 0x00,
            0x00, 0x01, 0x00, 0x01,
        )
        val resp = DnsOnionAutomapReply.buildAResponse(dns, 0, dns.size, a)
        assertTrue(resp != null && resp!!.size > dns.size)
        val parsed = DnsPacketParser.parse(resp!!, 0, resp.size)
        assertTrue(parsed != null && parsed!!.aRecords.contains(a))
        OnionAutomapAllocator.clear()
        DnsHostnameCache.clear()
    }
}
