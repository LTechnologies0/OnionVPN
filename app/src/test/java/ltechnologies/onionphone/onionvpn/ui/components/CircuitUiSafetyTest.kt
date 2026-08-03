package ltechnologies.onionphone.onionvpn.ui.components

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CircuitUiSafetyTest {
    @Test
    fun redactSocksAuth_hidesRawEpochForms() {
        assertEquals("DNSCrypt", redactSocksAuthForUi("dnscrypt"))
        assertEquals("DNSCrypt", redactSocksAuthForUi("dnscrypt-n3"))
        assertEquals("app uid=10123", redactSocksAuthForUi("u10123"))
        assertEquals("app uid=10123", redactSocksAuthForUi("u10123-n2"))
        assertEquals("PAC", redactSocksAuthForUi("pac"))
        assertEquals("isolated", redactSocksAuthForUi("mystery-token"))
        assertEquals("—", redactSocksAuthForUi(null))
    }

    @Test
    fun formatCountryHopPath_flagsOnlyNoIps() {
        val path = formatCountryHopPath(listOf("nl", "de", "us"))
        assertTrue(path.contains("NL"))
        assertTrue(path.contains("DE"))
        assertFalse(path.contains("."))
        assertFalse(path.contains(":"))
    }

    @Test
    fun formatByteCount_human() {
        assertEquals("512 B", formatByteCount(512))
        assertTrue(formatByteCount(2048).contains("KiB"))
    }
}
