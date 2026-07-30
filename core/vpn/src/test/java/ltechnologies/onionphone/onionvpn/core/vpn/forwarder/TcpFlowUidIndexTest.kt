package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketInfo
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

class TcpFlowUidIndexTest {
    @Before
    fun clear() {
        TcpFlowUidIndex.clear()
    }

    @Test
    fun peekKeepsStampForParallelConnects() {
        TcpFlowUidIndex.note(info(srcPort = 40000, dstIp = 0x08080808, dstPort = 443), uid = 10100)
        val a = TcpFlowUidIndex.peek(0x08080808, 443)
        val b = TcpFlowUidIndex.peek(0x08080808, 443)
        assertNotNull(a)
        assertNotNull(b)
        assertEquals(10100, a!!.uid)
        assertEquals(10100, b!!.uid)
    }

    @Test
    fun takeReturnsNewestUidForDestination() {
        val synA = info(srcPort = 40000, dstIp = 0x08080808, dstPort = 443)
        val synB = info(srcPort = 40001, dstIp = 0x08080808, dstPort = 443)
        TcpFlowUidIndex.note(synA, uid = 10100)
        TcpFlowUidIndex.note(synB, uid = 10200)
        val taken = TcpFlowUidIndex.take(0x08080808, 443)
        assertNotNull(taken)
        assertEquals(10200, taken!!.uid)
        assertEquals(40001, taken.srcPort)
        val older = TcpFlowUidIndex.take(0x08080808, 443)
        assertEquals(10100, older!!.uid)
        assertNull(TcpFlowUidIndex.take(0x08080808, 443))
    }

    @Test
    fun takeIpv4HostParsesDottedQuad() {
        TcpFlowUidIndex.note(info(dstIp = 0x01020304, dstPort = 80), uid = 99)
        val e = TcpFlowUidIndex.takeIpv4Host("1.2.3.4", 80)
        assertEquals(99, e!!.uid)
    }

    private fun info(
        srcPort: Int = 12345,
        dstIp: Int = 0x08080808,
        dstPort: Int = 443,
    ) = IpPacketInfo(
        protocol = IpPacketParser.PROTO_TCP,
        srcIpInt = 0x0A080002,
        dstIpInt = dstIp,
        srcPort = srcPort,
        dstPort = dstPort,
        isTcpSyn = true,
        isTcp = true,
        isUdp = false,
    )
}
