package ltechnologies.onionphone.onionvpn.core.tor.arti

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ArtiLogSanitizerTest {
    @Test
    fun stripAnsi_removesColorCodes() {
        val raw =
            "\u001B[2m2026-07-31T15:33:28.732593Z\u001B[0m \u001B[32m INFO\u001B[0m " +
                "\u001B[2marti_mobile_ex\u001B[0m\u001B[2m:\u001B[0m AMEx: state changed to Initialized"
        val clean = ArtiLogSanitizer.stripAnsi(raw)
        assertEquals(
            "2026-07-31T15:33:28.732593Z  INFO arti_mobile_ex: AMEx: state changed to Initialized",
            clean,
        )
        assertTrue(!clean.contains('\u001B'))
    }

    @Test
    fun normalizeLine_dropsBlankAfterStrip() {
        assertNull(ArtiLogSanitizer.normalizeLine("\u001B[0m\n"))
        assertNull(ArtiLogSanitizer.normalizeLine("   "))
    }

    @Test
    fun lineBuffer_splitsChunksOnNewline() {
        val lines = mutableListOf<String>()
        val buf = ArtiLogLineBuffer { lines += it }
        buf.accept("\u001B[32m INFO\u001B[0m hello")
        assertTrue(lines.isEmpty())
        buf.accept(" world\n\u001B[33m WARN\u001B[0m next")
        assertEquals(listOf("INFO hello world"), lines)
        buf.accept(" line\n")
        assertEquals(listOf("INFO hello world", "WARN next line"), lines)
    }
}
