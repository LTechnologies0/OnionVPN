package ltechnologies.onionphone.onionvpn.core.vpn.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsPacketParserTest {
    @Test
    fun parseQueryQname() {
        // DNS query for www.example.com type A
        val dns = buildDnsQuery("www.example.com")
        val parsed = DnsPacketParser.parse(dns, 0, dns.size)
        assertNotNull(parsed)
        assertEquals("www.example.com", parsed!!.qname)
        assertFalse(parsed.isResponse)
        assertTrue(parsed.aRecords.isEmpty())
    }

    @Test
    fun parseResponseARecords() {
        val qname = "ads.tracker.test"
        val query = buildDnsQuery(qname)
        val response = buildDnsResponse(query, listOf(0x0A, 0x14, 0x00, 0x01)) // 10.20.0.1
        val parsed = DnsPacketParser.parse(response, 0, response.size)
        assertNotNull(parsed)
        assertTrue(parsed!!.isResponse)
        assertEquals(qname, parsed.qname)
        assertEquals(listOf("10.20.0.1"), parsed.aRecords)
    }

    private fun buildDnsQuery(name: String): ByteArray {
        val labels = name.split('.')
        val nameBytes = labels.sumOf { 1 + it.length } + 1
        val buf = ByteArray(12 + nameBytes + 4)
        buf[0] = 0x12
        buf[1] = 0x34 // id
        buf[2] = 0x01 // RD
        buf[5] = 0x01 // qdcount = 1
        var pos = 12
        for (label in labels) {
            buf[pos++] = label.length.toByte()
            for (ch in label) buf[pos++] = ch.code.toByte()
        }
        buf[pos++] = 0
        buf[pos++] = 0
        buf[pos++] = 1 // A
        buf[pos++] = 0
        buf[pos] = 1 // IN
        return buf
    }

    private fun buildDnsResponse(query: ByteArray, ipv4: List<Int>): ByteArray {
        val out = ByteArray(query.size + 16)
        System.arraycopy(query, 0, out, 0, query.size)
        out[2] = (0x80 or 0x01).toByte() // QR + RD
        out[3] = 0x80.toByte() // RA
        out[7] = 1 // ancount
        var pos = query.size
        // name pointer to offset 12
        out[pos++] = 0xc0.toByte()
        out[pos++] = 0x0c
        out[pos++] = 0
        out[pos++] = 1 // A
        out[pos++] = 0
        out[pos++] = 1 // IN
        out[pos++] = 0
        out[pos++] = 0
        out[pos++] = 0
        out[pos++] = 60 // TTL
        out[pos++] = 0
        out[pos++] = 4 // rdlength
        for (b in ipv4) out[pos++] = b.toByte()
        return out
    }
}
