package ltechnologies.onionphone.onionvpn.core.tor.control.protocol

import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlEvent
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TorControlProtocolTest {
    @Test
    fun parseBootstrapEvent_progressAndSummary() {
        val raw =
            """STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=80 TAG=almost_done SUMMARY="Finishing handshake with directory server""""
        val boot = TorControlEventParser.parseBootstrapEvent(raw)
        assertNotNull(boot)
        assertEquals(80, boot!!.progress)
        assertEquals("almost_done", boot.tag)
        assertTrue(boot.summary.contains("Finishing handshake"))
    }

    @Test
    fun parseBootstrapPhase_done() {
        val raw = """NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done""""
        val boot = TorControlEventParser.parseBootstrapPhase(raw)
        assertNotNull(boot)
        assertEquals(100, boot!!.progress)
        assertEquals("done", boot.tag)
    }

    @Test
    fun multilineValue_singleLine() {
        val lines = listOf(
            "250-status/circuit-established=1",
            "250 OK",
        )
        assertEquals("1", TorControlReplyParser.multilineValue(lines, "status/circuit-established"))
    }

    @Test
    fun multilineValue_dataBlock() {
        val lines = listOf(
            "250+circuit-status=",
            "1 BUILT aaa,bbb BUILD_FLAGS=IS_INTERNAL PURPOSE=GENERAL",
            "2 BUILT ccc,ddd PURPOSE=GENERAL",
            ".",
            "250 OK",
        )
        val body = TorControlReplyParser.multilineValue(lines, "circuit-status")
        assertTrue(body.contains("1 BUILT"))
        assertTrue(body.contains("2 BUILT"))
    }

    @Test
    fun terminalReply_doesNotMatchCircuitIdsIn500Range() {
        // Regression: naive "5xx " check treated GETINFO body "517 EXTENDED" as control error.
        assertTrue(TorControlReplyParser.isTerminalReplyLine("250 OK"))
        assertTrue(TorControlReplyParser.isTerminalReplyLine("251 Order processed"))
        assertTrue(TorControlReplyParser.isErrorReplyLine("511 Authentication required."))
        assertTrue(TorControlReplyParser.isErrorReplyLine("552 Unrecognized option"))
        assertTrue(TorControlReplyParser.isMultilineDataStart("250+circuit-status="))
        assertTrue(TorControlReplyParser.isMultilineDataStart("250+stream-status="))
        // These match isErrorReplyLine shape but must only appear inside 250+ bodies —
        // transport ignores terminals while inMultilineData.
        assertTrue(TorControlReplyParser.isErrorReplyLine("517 EXTENDED foo"))
        assertTrue(TorControlReplyParser.isErrorReplyLine("503 NEWRESOLVE 0 example.com:0"))
        assertTrue(!TorControlReplyParser.isMultilineDataStart("250-circuit-status="))
        assertTrue(!TorControlReplyParser.isTerminalReplyLine("250-circuit-status="))
    }

    @Test
    fun multilineValue_preservesIdsIn500Range() {
        val lines = listOf(
            "250+circuit-status=",
            "517 EXTENDED \$AAA~a,\$BBB~b BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL",
            "585 BUILT \$CCC~c PURPOSE=GENERAL",
            ".",
            "250 OK",
        )
        val body = TorControlReplyParser.multilineValue(lines, "circuit-status")
        assertTrue(body.contains("517 EXTENDED"))
        assertTrue(body.contains("585 BUILT"))
    }

    @Test
    fun parseAsync_addrmapQuotedExpiry() {
        val parsed = TorControlEventParser.parseAsyncPayload(
            """ADDRMAP example.com 93.184.216.34 "2026-07-30 12:00:00"""",
        )
        val ev = parsed.event as TorControlEvent.AddrMap
        assertEquals("example.com", ev.address)
        assertEquals("93.184.216.34", ev.newAddress)
    }

    @Test
    fun parseAsync_streamUpdatesStatus() {
        val parsed = TorControlEventParser.parseAsyncPayload(
            "STREAM 5 FAILED 0 example.com:443 REASON=TIMEOUT",
        )
        assertNotNull(parsed.event)
        val patched = parsed.statusPatch(
            ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlStatus(),
        )
        assertEquals(1, patched.failedStreamsRecent)
        assertTrue(patched.lastStreamEvent.contains("FAILED"))
    }
}
