package ltechnologies.onionphone.onionvpn.core.tor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TorControlClientTest {
    @Test
    fun parseBootstrapEvent_progressAndSummary() {
        val raw =
            """STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=80 TAG=almost_done SUMMARY="Finishing handshake with directory server""""
        val boot = TorControlClient.parseBootstrapEvent(raw)
        assertNotNull(boot)
        assertEquals(80, boot!!.progress)
        assertEquals("almost_done", boot.tag)
        assertTrue(boot.summary.contains("Finishing handshake"))
    }

    @Test
    fun parseBootstrapPhase_done() {
        val raw = """NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done""""
        val boot = TorControlClient.parseBootstrapPhase(raw)
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
        assertEquals("1", TorControlClient.multilineValue(lines, "status/circuit-established"))
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
        val body = TorControlClient.multilineValue(lines, "circuit-status")
        assertTrue(body.contains("1 BUILT"))
        assertTrue(body.contains("2 BUILT"))
    }
}
