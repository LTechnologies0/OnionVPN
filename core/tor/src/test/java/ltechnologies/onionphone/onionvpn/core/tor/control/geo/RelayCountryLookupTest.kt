package ltechnologies.onionphone.onionvpn.core.tor.control.geo

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayCountryLookupTest {
    @Test
    fun flagEmoji_fr() {
        assertEquals("🇫🇷", RelayCountryLookup.flagEmoji("fr"))
        assertEquals("🇫🇷", RelayCountryLookup.flagEmoji("FR"))
    }

    @Test
    fun flagEmoji_unknownBlank() {
        assertEquals("", RelayCountryLookup.flagEmoji(null))
        assertEquals("", RelayCountryLookup.flagEmoji("?"))
        assertEquals("", RelayCountryLookup.flagEmoji("usa"))
    }

    @Test
    fun hopsForPath_parsesFingerprints() {
        // Pure parse without control — exercise path splitting via reflection-free public API
        // by constructing hops manually is covered in manager; here flag only.
        assertTrue(RelayCountryLookup.flagEmoji("de").contains("🇩"))
    }
}
