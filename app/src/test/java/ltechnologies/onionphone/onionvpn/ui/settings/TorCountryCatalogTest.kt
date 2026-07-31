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
}
