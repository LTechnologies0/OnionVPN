package ltechnologies.onionphone.onionvpn.core.vpn.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

class DnsHostnameCacheTest {
    @Before
    fun clear() {
        DnsHostnameCache.clear()
    }

    @Test
    fun putIpv4_enablesReverseLookup() {
        DnsHostnameCache.put("1.2.3.4", "www.example.com")
        assertEquals("www.example.com", DnsHostnameCache.lookup("1.2.3.4"))
        assertEquals("1.2.3.4", DnsHostnameCache.ipv4ForHostname("www.example.com"))
        assertEquals("1.2.3.4", DnsHostnameCache.ipv4ForHostname("WWW.EXAMPLE.COM"))
    }

    @Test
    fun putKeepsFirstIpv4_ignoresLater() {
        DnsHostnameCache.put("1.2.3.4", "cdn.example.com")
        DnsHostnameCache.put("5.6.7.8", "cdn.example.com")
        assertEquals("1.2.3.4", DnsHostnameCache.ipv4ForHostname("cdn.example.com"))
    }

    @Test
    fun automapVirtual_notPinnedAsClearnetIpv4() {
        DnsHostnameCache.put("10.192.0.50", "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion")
        assertNull(DnsHostnameCache.ipv4ForHostname("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"))
        assertEquals(
            "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
            DnsHostnameCache.lookup("10.192.0.50"),
        )
    }
}
