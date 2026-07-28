package ltechnologies.onionphone.onionvpn.threat

import java.io.StringReader
import ltechnologies.onionphone.onionvpn.core.model.DomainThreatCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainReputationIndexTest {
    @Test
    fun parentDomainMatching() {
        val set = hashSetOf("doubleclick.net", "metrics.apple.com")
        assertTrue(DomainReputationIndex.matches(set, "ad.doubleclick.net"))
        assertTrue(DomainReputationIndex.matches(set, "doubleclick.net"))
        assertTrue(DomainReputationIndex.matches(set, "a.b.metrics.apple.com"))
        assertFalse(DomainReputationIndex.matches(set, "example.com"))
        assertFalse(DomainReputationIndex.matches(set, "notdoubleclick.net"))
    }

    @Test
    fun malwareTakesPriorityOverTracking() {
        val index = DomainReputationIndex()
        index.replaceMalware(setOf("evil.example"))
        index.replaceTracking(setOf("evil.example", "ads.cdn.test"))
        assertEquals(DomainThreatCategory.MALWARE, index.classify("c2.evil.example"))
        assertEquals(DomainThreatCategory.TRACKING, index.classify("x.ads.cdn.test"))
        assertEquals(DomainThreatCategory.NONE, index.classify("safe.example"))
        assertEquals(DomainThreatCategory.NONE, index.classify("1.2.3.4"))
    }

    @Test
    fun parsePlainAndHostsLines() {
        val text = """
            # comment
            ! also comment
            doubleclick.net
            0.0.0.0 ads.tracker.test
            127.0.0.1 telemetry.oem.test
        """.trimIndent()
        val into = HashSet<String>()
        assertTrue(DomainReputationIndex.parseDomains(StringReader(text), into))
        assertTrue(into.contains("doubleclick.net"))
        assertTrue(into.contains("ads.tracker.test"))
        assertTrue(into.contains("telemetry.oem.test"))
    }
}
