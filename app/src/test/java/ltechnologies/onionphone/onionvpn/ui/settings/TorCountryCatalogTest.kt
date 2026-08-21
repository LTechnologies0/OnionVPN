package ltechnologies.onionphone.onionvpn.ui.settings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TorCountryCatalogTest {
    @Test
    fun encodeDecode_roundTrip() {
        val raw = TorCountryCatalog.encodeNodeCodes(setOf("de", "us", "fr"))
        assertEquals("{de},{fr},{us}", raw)
        assertEquals(setOf("de", "fr", "us"), TorCountryCatalog.parseNodeCodes(raw))
    }

    @Test
    fun parse_toleratesBareCodes() {
        assertEquals(setOf("no", "se"), TorCountryCatalog.parseNodeCodes("no, se"))
    }

    @Test
    fun fourteenEyes_includesFiveEyes() {
        val five = TorCountryCatalog.federations.first { it.id == "five_eyes" }.codes
        val fourteen = TorCountryCatalog.federations.first { it.id == "fourteen_eyes" }.codes
        assertTrue(fourteen.containsAll(five))
    }

    @Test
    fun euEeaSchengen_includeTorGeoIpEu() {
        val eu = TorCountryCatalog.federations.first { it.id == "eu" }.codes
        val eea = TorCountryCatalog.federations.first { it.id == "eea" }.codes
        val schengen = TorCountryCatalog.federations.first { it.id == "schengen" }.codes
        assertTrue("eu federation must include Tor GeoIP {eu}", eu.contains("eu"))
        assertTrue("eea must include eu", eea.contains("eu"))
        assertTrue("schengen must include eu", schengen.contains("eu"))
        assertTrue("eea must contain all eu members+tag", eea.containsAll(eu))
        assertTrue(
            "countries list must expose Tor GeoIP eu for manual ExcludeNodes",
            TorCountryCatalog.countries.any { it.code == "eu" },
        )
    }

    @Test
    fun migrateLegacyEuExclude_addsEuTag() {
        // Member states only (pre-fix federation) — must inject {eu}.
        val legacy = TorCountryCatalog.encodeNodeCodes(
            setOf(
                "at", "be", "bg", "hr", "cy", "cz", "dk", "ee", "fi", "fr", "de", "gr", "hu",
                "ie", "it", "lv", "lt", "lu", "mt", "nl", "pl", "pt", "ro", "sk", "si", "es", "se",
            ),
        )
        val migrated = TorCountryCatalog.ensureTorGeoIpEuInEuropeanExcludes(legacy)
        assertTrue(TorCountryCatalog.parseNodeCodes(migrated).contains("eu"))
    }
}
