package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IcmpUnreachableTest {
    @Test
    fun ipv4Udp_buildsPortUnreachable() {
        val original = ipv4Udp(
            srcIp = byteArrayOf(10, 8, 0, 2),
            dstIp = byteArrayOf(1, 1, 1, 1),
            srcPort = 40_000,
            dstPort = 443,
            payload = byteArrayOf(0xC0.toByte(), 0x00, 0x00, 0x00, 0x01),
        )
        val icmp = IcmpUnreachable.buildIpv4PortUnreachable(original, original.size)
        assertNotNull(icmp)
        val pkt = icmp!!
        assertEquals(0x45, pkt[0].toInt() and 0xff)
        assertEquals(1, pkt[9].toInt() and 0xff) // ICMP
        // Reply src = original dst
        assertEquals(1, pkt[12].toInt() and 0xff)
        assertEquals(1, pkt[13].toInt() and 0xff)
        // Reply dst = original src
        assertEquals(10, pkt[16].toInt() and 0xff)
        assertEquals(8, pkt[17].toInt() and 0xff)
        assertEquals(3, pkt[20].toInt() and 0xff) // type dest-unreach
        assertEquals(3, pkt[21].toInt() and 0xff) // code port-unreach
        // Quoted original IP starts after ICMP header
        assertEquals(0x45, pkt[28].toInt() and 0xff)
        assertTrue(pkt.size >= 28 + 20 + 8)
    }

    private fun ipv4Udp(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val ihl = 20
        val udpLen = 8 + payload.size
        val total = ihl + udpLen
        val pkt = ByteArray(total)
        pkt[0] = 0x45
        pkt[2] = (total ushr 8).toByte()
        pkt[3] = (total and 0xff).toByte()
        pkt[8] = 64
        pkt[9] = 17
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)
        pkt[ihl] = (srcPort ushr 8).toByte()
        pkt[ihl + 1] = (srcPort and 0xff).toByte()
        pkt[ihl + 2] = (dstPort ushr 8).toByte()
        pkt[ihl + 3] = (dstPort and 0xff).toByte()
        pkt[ihl + 4] = (udpLen ushr 8).toByte()
        pkt[ihl + 5] = (udpLen and 0xff).toByte()
        System.arraycopy(payload, 0, pkt, ihl + 8, payload.size)
        return pkt
    }
}
