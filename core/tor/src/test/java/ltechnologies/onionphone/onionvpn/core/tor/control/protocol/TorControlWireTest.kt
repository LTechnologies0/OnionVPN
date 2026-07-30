package ltechnologies.onionphone.onionvpn.core.tor.control.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class TorControlWireTest {
    @Test
    fun quotedString_escapesBackslashAndQuote() {
        assertEquals("\"plain\"", TorControlWire.quotedString("plain"))
        assertEquals("\"a\\\\b\"", TorControlWire.quotedString("a\\b"))
        assertEquals("\"say \\\"hi\\\"\"", TorControlWire.quotedString("say \"hi\""))
    }

    @Test
    fun requireHostname_rejectsCrLf() {
        assertEquals("example.com", TorControlWire.requireHostname("example.com"))
        assertThrows(Exception::class.java) {
            TorControlWire.requireHostname("evil.com\r\nSIGNAL SHUTDOWN")
        }
        assertThrows(Exception::class.java) {
            TorControlWire.requireHostname("has space.com")
        }
    }

    @Test
    fun requireId_andFingerprint() {
        assertEquals("517", TorControlWire.requireCircuitOrStreamId("517"))
        assertThrows(Exception::class.java) {
            TorControlWire.requireCircuitOrStreamId("517 EXTENDED")
        }
        assertEquals(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            TorControlWire.requireFingerprintHex("\$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        )
        assertFalse(runCatching { TorControlWire.requireFingerprintHex("short") }.isSuccess)
    }
}
