package ltechnologies.onionphone.onionvpn.core.tor.control.protocol

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TorStatusListParserTest {
    @Test
    fun parseCircuitLine_withSocksAuthAndPath() {
        val line =
            """42 BUILT ${'$'}AAA~Guard,${'$'}BBB~Mid,${'$'}CCC~Exit BUILD_FLAGS=READY PURPOSE=GENERAL """ +
                """TIME_CREATED=2024-01-01T00:00:00.000000 SOCKS_USERNAME="u10087" SOCKS_PASSWORD="p10087""""
        val c = TorStatusListParser.parseCircuitLine(line)
        assertNotNull(c)
        assertEquals("42", c!!.id)
        assertEquals("BUILT", c.status)
        assertTrue(c.path.contains("Guard"))
        assertEquals("GENERAL", c.purpose)
        assertEquals("u10087", c.socksUsername)
        assertEquals("p10087", c.socksPassword)
    }

    @Test
    fun parseStreamEvent_withSocksUsername() {
        val parsed = TorControlEventParser.parseAsyncPayload(
            """STREAM 15 SUCCEEDED 3 93.184.216.34:443 PURPOSE=USER CLIENT_PROTOCOL=SOCKS5 """ +
                """SOCKS_USERNAME="u10087" SOCKS_PASSWORD="p10087" SOURCE_ADDR=10.8.0.2:45678""",
        )
        val event = parsed.event as TorControlEvent.Stream
        assertEquals("15", event.id)
        assertEquals("SUCCEEDED", event.status)
        assertEquals("3", event.circuitId)
        assertEquals("u10087", event.socksUsername)
        assertEquals("p10087", event.socksPassword)
        assertEquals("SOCKS5", event.clientProtocol)
        assertEquals("10.8.0.2:45678", event.sourceAddr)
    }

    @Test
    fun socksUserForUid_roundTrip() {
        assertEquals("u10087", TunnelEndpoints.socksUserForUid(10087))
        assertEquals("p10087", TunnelEndpoints.socksPassForUid(10087))
        assertEquals(10087, TunnelEndpoints.uidFromSocksUser("u10087"))
        assertEquals(TunnelEndpoints.SOCKS_UNKNOWN_USER, TunnelEndpoints.socksUserForUid(-1))
        assertNull(TunnelEndpoints.uidFromSocksUser("dnscrypt"))
    }

    @Test
    fun parseCircuitStatus_multiline() {
        val body = """
            1 BUILT aaa,bbb PURPOSE=GENERAL
            2 BUILT ccc,ddd PURPOSE=GENERAL SOCKS_USERNAME="u1" SOCKS_PASSWORD="p1"
        """.trimIndent()
        val list = TorStatusListParser.parseCircuitStatus(body)
        assertEquals(2, list.size)
        assertEquals("u1", list[1].socksUsername)
    }
}
