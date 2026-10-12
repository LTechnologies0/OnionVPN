package ltechnologies.onionphone.onionvpn.core.vpn.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsTruncatedReplyTest {
    @Test
    fun headerOnly_setsQrTcRaAndCopiesId() {
        val reply = DnsTruncatedReply.headerOnly(queryId = 0x1234, queryFlags = 0x0100)
        assertEquals(12, reply.size)
        assertEquals(0x12, reply[0].toInt() and 0xff)
        assertEquals(0x34, reply[1].toInt() and 0xff)
        val flags = ((reply[2].toInt() and 0xff) shl 8) or (reply[3].toInt() and 0xff)
        assertTrue("QR", flags and 0x8000 != 0)
        assertTrue("TC", flags and 0x0200 != 0)
        assertTrue("RD copied", flags and 0x0100 != 0)
        assertTrue("RA", flags and 0x0080 != 0)
        assertTrue(DnsTruncatedReply.isTruncated(reply))
        assertEquals(0, reply[4].toInt() or reply[5].toInt()) // QDCOUNT
    }
}
