package ltechnologies.onionphone.onionvpn.core.tor.control.geo

import ltechnologies.onionphone.onionvpn.core.tor.control.TorControlClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
        assertTrue(RelayCountryLookup.flagEmoji("de").contains("🇩"))
    }

    /**
     * Regression: ConcurrentHashMap rejects null values. Disconnected control used to
     * `countryByFp[fp] = null` and crash Circuits refresh on Dispatchers.IO.
     */
    @Test
    fun countryForFingerprint_disconnected_cachesUnknownWithoutNpe() {
        val lookup = RelayCountryLookup(TorControlClient())
        val fp = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        assertNull(lookup.countryForFingerprint(fp))
        assertNull(lookup.countryForFingerprint(fp))
        val hops = lookup.hopsForPath("\$$fp~Unnamed")
        assertEquals(1, hops.size)
        assertNull(hops[0].countryCode)
    }
}
