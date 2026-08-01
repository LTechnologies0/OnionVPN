package ltechnologies.onionphone.onionvpn.core.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Domain / DNS / IP / packet policy: valid → Pass route; invalid → Drop / Fail.
 * Clearnet → DNSCrypt-over-Tor; onion → Automap; never clearnet DNS.
 */
class TorNetPolicyTest {
    @Test
    fun clearnetHostname_routesDnsCryptOverTor() {
        assertTrue(TorNetPolicy.isValidClearnetHostname("example.com"))
        assertTrue(TorNetPolicy.isValidClearnetHostname("www.torproject.org"))
        assertEquals(
            TorNetPolicy.DnsRoute.DnsCryptOverTor,
            TorNetPolicy.classifyDnsQuery("example.com"),
        )
        assertEquals(
            TorNetPolicy.DnsRoute.DnsCryptOverTor,
            TorNetPolicy.classifyDnsQuery("www.example.com."),
        )
    }

    @Test
    fun realOnion_routesTorAutomap() {
        val ddg = TunnelEndpoints.WELL_KNOWN_ONION_DDG
        assertTrue(TorNetPolicy.isValidDnsHostname(ddg))
        assertEquals(TorNetPolicy.DnsRoute.TorAutomap, TorNetPolicy.classifyDnsQuery(ddg))
        assertEquals(
            TorNetPolicy.DnsRoute.TorAutomap,
            TorNetPolicy.classifyDnsQuery("adb.onion"), // malformed but Automap-candidate
        )
    }

    @Test
    fun invalidHostnames_drop() {
        assertEquals(TorNetPolicy.DnsRoute.Drop, TorNetPolicy.classifyDnsQuery(null))
        assertEquals(TorNetPolicy.DnsRoute.Drop, TorNetPolicy.classifyDnsQuery(""))
        assertEquals(TorNetPolicy.DnsRoute.Drop, TorNetPolicy.classifyDnsQuery(" "))
        assertEquals(TorNetPolicy.DnsRoute.Drop, TorNetPolicy.classifyDnsQuery("singlelabel"))
        assertEquals(TorNetPolicy.DnsRoute.Drop, TorNetPolicy.classifyDnsQuery("has_under.score.com"))
        assertEquals(TorNetPolicy.DnsRoute.Drop, TorNetPolicy.classifyDnsQuery("evil.com\r\nATTACK"))
        assertEquals(TorNetPolicy.DnsRoute.Drop, TorNetPolicy.classifyDnsQuery("-bad.example.com"))
        assertFalse(TorNetPolicy.isValidClearnetHostname(TunnelEndpoints.WELL_KNOWN_ONION_DDG))
    }

    @Test
    fun socksDestination_validAndInvalid() {
        assertTrue(TorNetPolicy.isValidSocksDestination("example.com"))
        assertTrue(TorNetPolicy.isValidSocksDestination(TunnelEndpoints.WELL_KNOWN_ONION_DDG))
        assertTrue(TorNetPolicy.isValidSocksDestination("192.0.2.1"))
        assertTrue(TorNetPolicy.isValidSocksDestination("2001:db8::1"))
        assertFalse(TorNetPolicy.isValidSocksDestination(""))
        assertFalse(TorNetPolicy.isValidSocksDestination("not a host"))
        assertFalse(TorNetPolicy.isValidSocksDestination("999.999.999.999"))
        assertFalse(TorNetPolicy.isValidPort(0))
        assertTrue(TorNetPolicy.isValidPort(443))
    }

    @Test
    fun ipv4Classification_documentationAndAutomap() {
        assertEquals(TorNetPolicy.IpClass.Documentation, TorNetPolicy.classifyIpv4Literal("192.0.2.1"))
        assertEquals(TorNetPolicy.IpClass.Documentation, TorNetPolicy.classifyIpv4Literal("198.51.100.1"))
        assertEquals(TorNetPolicy.IpClass.TorAutomap, TorNetPolicy.classifyIpv4Literal("10.192.0.42"))
        assertEquals(TorNetPolicy.IpClass.VpnTun, TorNetPolicy.classifyIpv4Literal("10.8.0.2"))
        assertEquals(TorNetPolicy.IpClass.GloballyRoutable, TorNetPolicy.classifyIpv4Literal("93.184.216.34"))
        assertEquals(TorNetPolicy.IpClass.Multicast, TorNetPolicy.classifyIpv4Literal("224.0.0.251"))
        assertEquals(TorNetPolicy.IpClass.LinkLocal, TorNetPolicy.classifyIpv4Literal("169.254.1.1"))
        assertEquals(TorNetPolicy.IpClass.Invalid, TorNetPolicy.classifyIpv4Literal("not-an-ip"))
        assertTrue(TorNetPolicy.mustBlackholeIpv4Destination(
            TunnelEndpoints.parseIpv4Literal("224.0.0.1")!!,
        ))
        assertFalse(TorNetPolicy.mustBlackholeIpv4Destination(
            TunnelEndpoints.parseIpv4Literal("93.184.216.34")!!,
        ))
    }

    @Test
    fun dnsAddressRecords_acceptRealShapes() {
        assertTrue(TorNetPolicy.isValidDnsAddressRecord("192.0.2.1"))
        assertTrue(TorNetPolicy.isValidDnsAddressRecord("10.192.0.1"))
        assertTrue(TorNetPolicy.isValidDnsAddressRecord("2001:db8::53"))
        assertFalse(TorNetPolicy.isValidDnsAddressRecord(""))
        assertFalse(TorNetPolicy.isValidDnsAddressRecord("hostname.example"))
    }

    @Test
    fun ipv4PacketHeader_validAndInvalid() {
        val ok = ByteArray(40)
        ok[0] = 0x45
        // Total Length 0 accepted (TUN quirk)
        assertTrue(TorNetPolicy.isWellFormedIpv4Packet(ok, 40))
        ok[2] = 0
        ok[3] = 40
        assertTrue(TorNetPolicy.isWellFormedIpv4Packet(ok, 40))
        ok[3] = 50 // claims 50 but buffer is 40
        assertFalse(TorNetPolicy.isWellFormedIpv4Packet(ok, 40))
        assertFalse(TorNetPolicy.isWellFormedIpv4Packet(ByteArray(10), 10))
        assertFalse(TorNetPolicy.isWellFormedTransportPorts(12345, 0))
        assertTrue(TorNetPolicy.isWellFormedTransportPorts(12345, 443))
    }
}
