package ltechnologies.onionphone.onionvpn.threat

import java.io.StringReader
import ltechnologies.onionphone.onionvpn.core.model.DomainThreatCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainListParserTest {
    @Test
    fun hostsAndPlain() {
        val text = """
            # comment
            doubleclick.net
            0.0.0.0 ads.tracker.test
            127.0.0.1 telemetry.oem.test
            <html>
        """.trimIndent()
        val into = HashSet<String>()
        assertTrue(DomainListParser.parse(StringReader(text), DomainListFormat.HOSTS, into) >= 3)
        assertTrue(into.containsAll(listOf("doubleclick.net", "ads.tracker.test", "telemetry.oem.test")))
    }

    @Test
    fun adblockExtractsHostBlocksOnly() {
        assertEquals("flexytalk.net", DomainListParser.extractAdblockHost("||flexytalk.net^"))
        assertEquals("01net.com", DomainListParser.extractAdblockHost("||01net.com^\$doc"))
        assertNull(DomainListParser.extractAdblockHost("||01net.com/telecharger/\$doc"))
        assertNull(
            DomainListParser.extractAdblockHost("||reddit.com^\$doc,removeparam=utm_content"),
        )
        assertFalse(DomainListParser.acceptDomain("1.2.3.4"))
    }

    @Test
    fun adblockPrivacySample() {
        val text = buildString {
            appendLine("! Title")
            appendLine("||ratexchange.net^")
            appendLine("||adnotbad.com^")
            appendLine("||reddit.com^\$doc,removeparam=ref")
            appendLine("||vidtech.cbsinteractive.com^*/tracking/\$script")
        }
        val into = HashSet<String>()
        DomainListParser.parse(StringReader(text), DomainListFormat.ADBLOCK_NETWORK, into)
        assertTrue(into.contains("ratexchange.net"))
        assertTrue(into.contains("adnotbad.com"))
        assertFalse(into.contains("reddit.com"))
        assertFalse(into.contains("vidtech.cbsinteractive.com"))
    }
}

class DomainBlocklistCatalogTest {
    @Test
    fun catalogCoversRequestedProviders() {
        val ids = DomainBlocklistCatalog.ALL.map { it.id }.toSet()
        assertTrue(ids.contains("urlhaus-hosts"))
        assertTrue(ids.contains("yoyo-adservers"))
        assertTrue(ids.contains("uassets-badware"))
        assertTrue(ids.contains("uassets-privacy"))
        assertTrue(ids.contains("hagezi-tif-mini"))
        assertTrue(ids.contains("hagezi-light"))
        assertTrue(
            DomainBlocklistCatalog.malwareSources().all {
                it.category == DomainThreatCategory.MALWARE
            },
        )
        assertTrue(
            DomainBlocklistCatalog.trackingSources().all {
                it.category == DomainThreatCategory.TRACKING
            },
        )
        assertTrue(DomainBlocklistCatalog.ALL.any { it.required })
    }
}
