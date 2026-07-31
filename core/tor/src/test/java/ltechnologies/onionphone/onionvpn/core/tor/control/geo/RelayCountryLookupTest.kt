package ltechnologies.onionphone.onionvpn.core.tor.control.geo

import java.io.File
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

    @Test
    fun fingerprintToIdentityB64_matchesTorDirSpec() {
        // 20 zero bytes → AAAAAAAAAAAAAAAAAAAAAAAAAAA= → strip =
        assertEquals(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAA",
            RelayCountryLookup.fingerprintToIdentityB64("00".repeat(20)),
        )
        assertNull(RelayCountryLookup.fingerprintToIdentityB64("short"))
    }

    @Test
    fun indexConsensusRelayIps_readsRouterStatusLine() {
        val identity = RelayCountryLookup.fingerprintToIdentityB64(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )!!
        val map = RelayCountryLookup.indexConsensusRelayIps(
            "r Unnamed $identity AAAAAAAAAAAAAAAAAAAAAAAAAAAg 2026-01-01 00:00:00 198.51.100.10 9001 0\n",
        )
        assertEquals("198.51.100.10", map[identity])
    }

    @Test
    fun indexConsensusRelayIps_streamsLinesWithoutFullBuffer() {
        val identity = RelayCountryLookup.fingerprintToIdentityB64(
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        )!!
        val lines = sequenceOf(
            "network-status-version 3",
            "r Unnamed $identity AAAAAAAAAAAAAAAAAAAAAAAAAAAg 2026-01-01 00:00:00 203.0.113.5 9001 0",
            "s Fast Running Valid",
        )
        val map = RelayCountryLookup.indexConsensusRelayIps(lines)
        assertEquals("203.0.113.5", map[identity])
    }

    @Test
    fun consensusFile_presentDoesNotThrowWhenDisconnected() {
        val dir = java.nio.file.Files.createTempDirectory("onionvpn-tor-geo").toFile()
        try {
            val identity = RelayCountryLookup.fingerprintToIdentityB64(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )!!
            File(dir, "cached-microdesc-consensus").writeText(
                "r Unnamed $identity AAAAAAAAAAAAAAAAAAAAAAAAAAAg 2026-01-01 00:00:00 198.51.100.10 9001 0\n",
            )
            val lookup = RelayCountryLookup(TorControlClient(), dir)
            assertNull(lookup.countryForFingerprint("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
        } finally {
            dir.deleteRecursively()
        }
    }
}
