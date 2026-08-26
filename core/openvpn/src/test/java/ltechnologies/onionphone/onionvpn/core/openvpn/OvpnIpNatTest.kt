package ltechnologies.onionphone.onionvpn.core.openvpn

import java.nio.ByteBuffer
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class OvpnIpNatTest {
    @Before
    fun setUp() {
        OvpnIpNat.clear()
    }

    @Test
    fun snatThenDnatRoundTripPreservesPayloadAndRestoresVpnAddresses() {
        OvpnIpNat.setFromIfconfigMsg("10.211.1.173 10.211.1.174 1280 net30")
        assertTrue(OvpnIpNat.isReady())

        val packet = buildTcpSyn(
            src = TunnelEndpoints.VPN_CLIENT_ADDRESS,
            dst = "93.184.216.34",
            srcPort = 50_000,
            dstPort = 443,
        )
        val len = packet.size
        assertTrue(OvpnIpNat.snatOutbound(packet, len))
        assertEquals("10.211.1.173", ipv4At(packet, 12))
        assertEquals("93.184.216.34", ipv4At(packet, 16))

        // SoftEther reply: swap addresses and ports
        val reply = packet.copyOf()
        System.arraycopy(packet, 12, reply, 16, 4)
        System.arraycopy(packet, 16, reply, 12, 4)
        // swap TCP ports
        reply[20] = packet[22]
        reply[21] = packet[23]
        reply[22] = packet[20]
        reply[23] = packet[21]
        reply[10] = 0
        reply[11] = 0
        val ihl = (reply[0].toInt() and 0xf) * 4
        val sum = onesComplement(reply, 0, ihl)
        reply[10] = (sum ushr 8).toByte()
        reply[11] = (sum and 0xff).toByte()

        assertTrue(OvpnIpNat.dnatInbound(reply, len))
        assertEquals(TunnelEndpoints.VPN_CLIENT_ADDRESS, ipv4At(reply, 16))
        assertEquals("93.184.216.34", ipv4At(reply, 12))
    }

    @Test
    fun dnatDropsUntrackedInbound() {
        OvpnIpNat.setFromIfconfigMsg("10.211.1.173 10.211.1.174 1280 net30")
        val packet = buildTcpSyn(
            src = "93.184.216.34",
            dst = "10.211.1.173",
            srcPort = 443,
            dstPort = 50_000,
        )
        assertFalse(OvpnIpNat.dnatInbound(packet, packet.size))
    }

    @Test
    fun snatFailsWhenIfconfigMissing() {
        val packet = buildTcpSyn(
            src = TunnelEndpoints.VPN_CLIENT_ADDRESS,
            dst = "1.1.1.1",
            srcPort = 12345,
            dstPort = 443,
        )
        assertFalse(OvpnIpNat.snatOutbound(packet, packet.size))
    }

    @Test
    fun dataPlaneSilentWhenSnatWithoutDnat() {
        OvpnIpNat.setFromIfconfigMsg("10.211.1.173 10.211.1.174 1280 net30")
        val packet = buildTcpSyn(
            src = TunnelEndpoints.VPN_CLIENT_ADDRESS,
            dst = "93.184.216.34",
            srcPort = 50_000,
            dstPort = 443,
        )
        assertTrue(OvpnIpNat.snatOutbound(packet, packet.size))
        assertTrue(OvpnIpNat.isDataPlaneSilent(silenceMs = 1_000L))
        assertEquals(1L, OvpnIpNat.snatRewriteCount)
        assertEquals(0L, OvpnIpNat.dnatRewriteCount)
    }

    @Test
    fun dataPlaneNotSilentAfterDnat() {
        OvpnIpNat.setFromIfconfigMsg("10.211.1.173 10.211.1.174 1280 net30")
        val packet = buildTcpSyn(
            src = TunnelEndpoints.VPN_CLIENT_ADDRESS,
            dst = "93.184.216.34",
            srcPort = 50_000,
            dstPort = 443,
        )
        val len = packet.size
        assertTrue(OvpnIpNat.snatOutbound(packet, len))
        val reply = packet.copyOf()
        System.arraycopy(packet, 12, reply, 16, 4)
        System.arraycopy(packet, 16, reply, 12, 4)
        reply[20] = packet[22]
        reply[21] = packet[23]
        reply[22] = packet[20]
        reply[23] = packet[21]
        assertTrue(OvpnIpNat.dnatInbound(reply, len))
        assertFalse(OvpnIpNat.isDataPlaneSilent(silenceMs = 20_000L))
    }

    private fun buildTcpSyn(src: String, dst: String, srcPort: Int, dstPort: Int): ByteArray {
        val buf = ByteArray(40) // 20 IP + 20 TCP
        buf[0] = 0x45.toByte()
        buf[2] = 0
        buf[3] = 40
        buf[8] = 64 // TTL
        buf[9] = 6 // TCP
        writeIp(buf, 12, src)
        writeIp(buf, 16, dst)
        buf[10] = 0
        buf[11] = 0
        val ipSum = onesComplement(buf, 0, 20)
        buf[10] = (ipSum ushr 8).toByte()
        buf[11] = (ipSum and 0xff).toByte()

        buf[20] = (srcPort ushr 8).toByte()
        buf[21] = srcPort.toByte()
        buf[22] = (dstPort ushr 8).toByte()
        buf[23] = dstPort.toByte()
        buf[32] = 0x50.toByte() // data offset 5
        buf[33] = 0x02.toByte() // SYN
        // TCP checksum with pseudo-header
        val tcpSum = tcpChecksum(buf, 20, 20, src, dst)
        buf[36] = (tcpSum ushr 8).toByte()
        buf[37] = (tcpSum and 0xff).toByte()
        return buf
    }

    private fun writeIp(buf: ByteArray, off: Int, dotted: String) {
        val p = dotted.split('.').map { it.toInt() }
        buf[off] = p[0].toByte()
        buf[off + 1] = p[1].toByte()
        buf[off + 2] = p[2].toByte()
        buf[off + 3] = p[3].toByte()
    }

    private fun ipv4At(buf: ByteArray, off: Int): String =
        "${buf[off].toInt() and 0xff}.${buf[off + 1].toInt() and 0xff}." +
            "${buf[off + 2].toInt() and 0xff}.${buf[off + 3].toInt() and 0xff}"

    private fun onesComplement(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((buf[i].toInt() and 0xff) shl 8) or (buf[i + 1].toInt() and 0xff)
            i += 2
        }
        if (i < end) sum += (buf[i].toInt() and 0xff) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.inv().toInt() and 0xffff
    }

    private fun tcpChecksum(
        packet: ByteArray,
        tcpOff: Int,
        tcpLen: Int,
        src: String,
        dst: String,
    ): Int {
        val bb = ByteBuffer.allocate(12 + tcpLen)
        writeIp(bb.array(), 0, src)
        writeIp(bb.array(), 4, dst)
        bb.put(8, 0)
        bb.put(9, 6)
        bb.putShort(10, tcpLen.toShort())
        System.arraycopy(packet, tcpOff, bb.array(), 12, tcpLen)
        // zero checksum field in copy
        bb.array()[12 + 16] = 0
        bb.array()[12 + 17] = 0
        return onesComplement(bb.array(), 0, 12 + tcpLen)
    }
}
