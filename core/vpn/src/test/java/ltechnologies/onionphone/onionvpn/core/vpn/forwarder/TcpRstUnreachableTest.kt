package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TcpRstUnreachableTest {
    @Test
    fun ipv4Syn_buildsRstAck() {
        val syn = ipv4TcpSyn(
            srcIp = byteArrayOf(10, 8, 0, 2),
            dstIp = byteArrayOf(1, 1, 1, 1),
            srcPort = 50_000,
            dstPort = 443,
            seq = 0x11111111,
        )
        val rst = TcpRstUnreachable.buildIpv4Rst(syn, syn.size)
        assertNotNull(rst)
        val pkt = rst!!
        assertEquals(6, pkt[9].toInt() and 0xff)
        // Reply src = original dst
        assertEquals(1, pkt[12].toInt() and 0xff)
        assertEquals(1, pkt[15].toInt() and 0xff)
        // Reply dst = original src
        assertEquals(10, pkt[16].toInt() and 0xff)
        assertEquals(2, pkt[19].toInt() and 0xff)
        val ihl = 20
        assertEquals(443, ((pkt[ihl].toInt() and 0xff) shl 8) or (pkt[ihl + 1].toInt() and 0xff))
        assertEquals(50_000, ((pkt[ihl + 2].toInt() and 0xff) shl 8) or (pkt[ihl + 3].toInt() and 0xff))
        val flags = pkt[ihl + 13].toInt() and 0xff
        assertTrue(flags and TcpPacketBuilder.FLAG_RST != 0)
        assertTrue(flags and TcpPacketBuilder.FLAG_ACK != 0)
        val ack = ((pkt[ihl + 8].toInt() and 0xff) shl 24) or
            ((pkt[ihl + 9].toInt() and 0xff) shl 16) or
            ((pkt[ihl + 10].toInt() and 0xff) shl 8) or
            (pkt[ihl + 11].toInt() and 0xff)
        assertEquals(0x11111111 + 1, ack)
    }

    @Test
    fun ipv6Syn_buildsRstAck() {
        val syn = ipv6TcpSyn(
            src = ByteArray(16) { if (it == 15) 2 else 0 }.also { it[0] = 0xfd.toByte() },
            dst = ByteArray(16) { 0x20 }.also { it[0] = 0x20; it[1] = 1 },
            srcPort = 40_000,
            dstPort = 443,
            seq = 0x22222222,
        )
        val rst = TcpRstUnreachable.buildIpv6Rst(syn, syn.size)
        assertNotNull(rst)
        val pkt = rst!!
        assertEquals(0x60, pkt[0].toInt() and 0xf0)
        assertEquals(6, pkt[6].toInt() and 0xff)
        // src of reply = original dst
        assertEquals(0x20, pkt[8].toInt() and 0xff)
        assertEquals(1, pkt[9].toInt() and 0xff)
        val t = 40
        val flags = pkt[t + 13].toInt() and 0xff
        assertTrue(flags and TcpPacketBuilder.FLAG_RST != 0)
        assertTrue(flags and TcpPacketBuilder.FLAG_ACK != 0)
    }

    @Test
    fun rstOfRst_returnsNull() {
        val syn = ipv4TcpSyn(
            srcIp = byteArrayOf(10, 8, 0, 2),
            dstIp = byteArrayOf(1, 1, 1, 1),
            srcPort = 1,
            dstPort = 443,
            seq = 1,
        )
        syn[20 + 13] = TcpPacketBuilder.FLAG_RST.toByte()
        assertNull(TcpRstUnreachable.buildIpv4Rst(syn, syn.size))
    }

    private fun ipv4TcpSyn(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        seq: Int,
    ): ByteArray {
        val pkt = ByteArray(40)
        pkt[0] = 0x45
        pkt[2] = 0
        pkt[3] = 40
        pkt[8] = 64
        pkt[9] = 6
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)
        val t = 20
        pkt[t] = (srcPort ushr 8).toByte()
        pkt[t + 1] = (srcPort and 0xff).toByte()
        pkt[t + 2] = (dstPort ushr 8).toByte()
        pkt[t + 3] = (dstPort and 0xff).toByte()
        pkt[t + 4] = (seq ushr 24).toByte()
        pkt[t + 5] = (seq ushr 16).toByte()
        pkt[t + 6] = (seq ushr 8).toByte()
        pkt[t + 7] = seq.toByte()
        pkt[t + 12] = 0x50
        pkt[t + 13] = TcpPacketBuilder.FLAG_SYN.toByte()
        return pkt
    }

    private fun ipv6TcpSyn(
        src: ByteArray,
        dst: ByteArray,
        srcPort: Int,
        dstPort: Int,
        seq: Int,
    ): ByteArray {
        val pkt = ByteArray(60)
        pkt[0] = 0x60
        pkt[4] = 0
        pkt[5] = 20
        pkt[6] = 6
        pkt[7] = 64
        System.arraycopy(src, 0, pkt, 8, 16)
        System.arraycopy(dst, 0, pkt, 24, 16)
        val t = 40
        pkt[t] = (srcPort ushr 8).toByte()
        pkt[t + 1] = (srcPort and 0xff).toByte()
        pkt[t + 2] = (dstPort ushr 8).toByte()
        pkt[t + 3] = (dstPort and 0xff).toByte()
        pkt[t + 4] = (seq ushr 24).toByte()
        pkt[t + 5] = (seq ushr 16).toByte()
        pkt[t + 6] = (seq ushr 8).toByte()
        pkt[t + 7] = seq.toByte()
        pkt[t + 12] = 0x50
        pkt[t + 13] = TcpPacketBuilder.FLAG_SYN.toByte()
        return pkt
    }
}
