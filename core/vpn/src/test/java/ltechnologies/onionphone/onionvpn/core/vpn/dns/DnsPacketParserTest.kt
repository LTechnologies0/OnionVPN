package ltechnologies.onionphone.onionvpn.core.vpn.dns

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsPacketParserTest {
    @Test
    fun parseQueryQname_exampleCom_passes() {
        val dns = buildDnsQuery("www.example.com")
        val parsed = DnsPacketParser.parse(dns, 0, dns.size)
        assertNotNull(parsed)
        assertEquals("www.example.com", parsed!!.qname)
        assertFalse(parsed.isResponse)
        assertTrue(parsed.aRecords.isEmpty())
    }

    @Test
    fun parseResponseARecords_rfc5737_passes() {
        val qname = "www.example.com"
        val query = buildDnsQuery(qname)
        // 192.0.2.1 TEST-NET-1
        val response = buildDnsResponse(query, listOf(192, 0, 2, 1))
        val parsed = DnsPacketParser.parse(response, 0, response.size)
        assertNotNull(parsed)
        assertTrue(parsed!!.isResponse)
        assertEquals(qname, parsed.qname)
        assertEquals(listOf("192.0.2.1"), parsed.aRecords)
    }

    @Test
    fun parseRealOnionQname_passes() {
        val onion = TunnelEndpoints.WELL_KNOWN_ONION_DDG
        val dns = buildDnsQuery(onion)
        val parsed = DnsPacketParser.parse(dns, 0, dns.size)
        assertNotNull(parsed)
        assertEquals(onion, parsed!!.qname)
    }

    @Test
    fun parseInjectionQname_fails() {
        val under = buildDnsQuery("has_under.example.com")
        assertNull(DnsPacketParser.parse(under, 0, under.size))
        val dots = buildDnsQuery("bad..example.com")
        assertNull(DnsPacketParser.parse(dots, 0, dots.size))
    }

    @Test
    fun parseSingleLabel_fails() {
        val dns = buildDnsQuery("localhost")
        assertNull(DnsPacketParser.parse(dns, 0, dns.size))
    }

    private fun buildDnsQuery(name: String): ByteArray {
        val labels = name.split('.')
        val nameBytes = labels.sumOf { 1 + it.length } + 1
        val buf = ByteArray(12 + nameBytes + 4)
        buf[0] = 0x12
        buf[1] = 0x34
        buf[2] = 0x01
        buf[5] = 0x01
        var pos = 12
        for (label in labels) {
            buf[pos++] = label.length.toByte()
            for (ch in label) buf[pos++] = ch.code.toByte()
        }
        buf[pos++] = 0
        buf[pos++] = 0
        buf[pos++] = 1
        buf[pos++] = 0
        buf[pos] = 1
        return buf
    }

    private fun buildDnsResponse(query: ByteArray, ipv4: List<Int>): ByteArray {
        val out = ByteArray(query.size + 16)
        System.arraycopy(query, 0, out, 0, query.size)
        out[2] = (0x80 or 0x01).toByte()
        out[3] = 0x80.toByte()
        out[7] = 1
        var pos = query.size
        out[pos++] = 0xc0.toByte()
        out[pos++] = 0x0c
        out[pos++] = 0
        out[pos++] = 1
        out[pos++] = 0
        out[pos++] = 1
        out[pos++] = 0
        out[pos++] = 0
        out[pos++] = 0
        out[pos++] = 60
        out[pos++] = 0
        out[pos++] = 4
        for (b in ipv4) out[pos++] = b.toByte()
        return out
    }
}
