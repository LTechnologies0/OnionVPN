package ltechnologies.onionphone.onionvpn.core.vpn.dns

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OnionAutomapRoutingTest {
    private val ddgOnion = TunnelEndpoints.WELL_KNOWN_ONION_DDG

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
    fun realOnion_routesToAutomap_fakeOnionRejectedByValidator() {
        assertTrue(TunnelEndpoints.isValidOnionHostname(ddgOnion))
        assertTrue(TunnelEndpoints.isOnionLikeHostname(ddgOnion))
        assertTrue(TunnelEndpoints.isOnionLikeHostname("$ddgOnion."))
        assertFalse(TunnelEndpoints.isValidOnionHostname("example.onion"))
        assertFalse(TunnelEndpoints.isValidOnionHostname("adb.onion"))
        assertFalse(TunnelEndpoints.isOnionLikeHostname("example.com"))
        assertFalse(TunnelEndpoints.isOnionLikeHostname("onion.com"))
        assertFalse(TunnelEndpoints.isOnionLikeHostname(""))
    }

    @Test
    fun hostnameCache_mapsAutomapIpToRealOnionForSocks5a() {
        DnsHostnameCache.clear()
        DnsHostnameCache.put("10.192.0.42", ddgOnion)
        val cached = DnsHostnameCache.lookup("10.192.0.42")!!
        assertTrue(TunnelEndpoints.isValidOnionHostname(cached))
        assertTrue(TunnelEndpoints.isOnionLikeHostname(cached))
        DnsHostnameCache.clear()
    }

    @Test
    fun artiAutomapAllocator_stableVirtualIpForRealOnion() {
        OnionAutomapAllocator.clear()
        DnsHostnameCache.clear()
        val a = OnionAutomapAllocator.ipv4ForHostname(ddgOnion)
        val b = OnionAutomapAllocator.ipv4ForHostname(ddgOnion)
        assertEquals(a, b)
        assertTrue(TunnelEndpoints.isAutomapVirtualIpv4(a))
        assertEquals(ddgOnion, DnsHostnameCache.lookup(a))

        val qname = encodeDnsName(ddgOnion)
        val dns = byteArrayOf(
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ) + qname + byteArrayOf(0x00, 0x01, 0x00, 0x01)
        val resp = DnsOnionAutomapReply.buildAResponse(dns, 0, dns.size, a)
        assertTrue(resp != null && resp!!.size > dns.size)
        val parsed = DnsPacketParser.parse(resp!!, 0, resp.size)
        assertTrue(parsed != null && parsed!!.aRecords.contains(a))
        OnionAutomapAllocator.clear()
        DnsHostnameCache.clear()
    }

    private fun encodeDnsName(hostname: String): ByteArray {
        val labels = hostname.trimEnd('.').lowercase().split('.')
        val out = ArrayList<Byte>()
        for (label in labels) {
            require(label.length in 1..63)
            out.add(label.length.toByte())
            for (c in label) out.add(c.code.toByte())
        }
        out.add(0)
        return out.toByteArray()
    }
}
