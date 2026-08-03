package ltechnologies.onionphone.onionvpn.core.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Locks Settings copy helpers to the capability matrix so UI claims cannot
 * contradict [TorEngineCapabilities] again.
 */
class TorEngineCapabilitiesCopyTest {

    @Test
    fun arti_capabilityMatrix_matchesRuntimeContract() {
        val a = TorEngine.ARTI.capabilities
        assertTrue(a.conjureBridges)
        assertTrue(a.exitCountryPrefs)
        assertTrue(a.liveCircuitTiming)
        assertTrue(a.synthesizeOnionAutomap)
        assertTrue(a.socksAuthIsolation)
        assertTrue(a.circuitInspection)
        assertTrue(a.multiSocksSessionGroups) // app-layer ArtiSocksRoleMux
        assertFalse(a.classicControlPlane)
        assertFalse(a.nodePrefs)
        assertFalse(a.torrcConfig)
        assertFalse(a.liveSetConf)
        assertFalse(a.nativeAutomapDnsPort)
    }

    @Test
    fun littleT_capabilityMatrix_hasFullControlPlane() {
        val c = TorEngine.LITTLE_T.capabilities
        assertTrue(c.classicControlPlane)
        assertTrue(c.multiSocksSessionGroups)
        assertTrue(c.torrcConfig)
        assertTrue(c.liveSetConf)
        assertTrue(c.circuitInspection)
        assertTrue(c.nodePrefs)
        assertTrue(c.conjureBridges)
        assertTrue(c.nativeAutomapDnsPort)
        assertFalse(c.synthesizeOnionAutomap)
    }

    @Test
    fun kotlinTor_capabilityMatrix_mirrorsLittleTHevSocksFlags() {
        val k = TorEngine.KOTLIN_TOR.capabilities
        val little = TorEngine.LITTLE_T.capabilities
        // HEV_SOCKS plane parity with little-t (ports / isolation / Automap / NEWNYM).
        assertEquals(little.classicControlPlane, k.classicControlPlane)
        assertEquals(little.multiSocksSessionGroups, k.multiSocksSessionGroups)
        assertEquals(little.socksAuthIsolation, k.socksAuthIsolation)
        assertEquals(little.nativeAutomapDnsPort, k.nativeAutomapDnsPort)
        assertEquals(little.synthesizeOnionAutomap, k.synthesizeOnionAutomap)
        assertEquals(little.newIdentity, k.newIdentity)
        assertTrue(k.dormantSignals)
        // kotlin-tor ControlServer is not full torrc SETCONF / Conjure yet.
        assertFalse(k.liveSetConf)
        assertFalse(k.torrcConfig)
        assertFalse(k.conjureBridges)
    }

    @Test
    fun arti_settingsSubtitle_mentionsRealCapabilities() {
        val text = TorEngine.ARTI.settingsSubtitle()
        assertTrue(text, text.contains("prediction_lifetime", ignoreCase = true))
        assertTrue(text, text.contains("Automap synth", ignoreCase = true) || text.contains("synth"))
        assertTrue(text, text.contains("SessionGroup", ignoreCase = true))
        assertTrue(text, text.contains("Conjure", ignoreCase = true))
        assertTrue(text, text.contains("Single-country Exit", ignoreCase = true))
        assertFalse(text, text.contains("No circuits UI", ignoreCase = true))
        assertFalse(text, text.contains("no Conjure", ignoreCase = true))
        assertFalse(text, text.contains("ControlPort SETCONF"))
    }

    @Test
    fun littleT_settingsSubtitle_mentionsControlPortAndSessionGroups() {
        val text = TorEngine.LITTLE_T.settingsSubtitle()
        assertTrue(text, text.contains("ControlPort", ignoreCase = true))
        assertTrue(text, text.contains("SessionGroup", ignoreCase = true))
        assertTrue(text, text.contains("Conjure", ignoreCase = true))
        assertTrue(text, text.contains("Entry/Exit/Exclude", ignoreCase = true))
        assertFalse(text, text.contains("No circuits UI"))
    }

    @Test
    fun arti_enginePickerHint_doesNotDenyConjure() {
        val text = TorEngine.ARTI.enginePickerHint()
        assertTrue(text, text.contains("Conjure supported", ignoreCase = true))
        assertFalse(text, text.contains("no circuits UI", ignoreCase = true))
        assertTrue(text, text.contains("Exit country only", ignoreCase = true))
        assertFalse(text, text.contains("no Conjure", ignoreCase = true))
        assertFalse(text, text.contains("shared SocksPort", ignoreCase = true))
    }

    @Test
    fun littleT_enginePickerHint_claimsFullFeatureSet() {
        val text = TorEngine.LITTLE_T.enginePickerHint()
        assertTrue(text, text.contains("ControlPort", ignoreCase = true))
        assertTrue(text, text.contains("Conjure supported", ignoreCase = true))
        assertFalse(text, text.contains("shared SocksPort", ignoreCase = true))
    }

    @Test
    fun kotlinTor_enginePickerHint_mentionsControlSurface() {
        val text = TorEngine.KOTLIN_TOR.enginePickerHint()
        assertTrue(text, text.contains("Kotlin Tor", ignoreCase = true))
        assertFalse(text, text.contains("shared SocksPort", ignoreCase = true))
        assertTrue(text, text.contains("no Conjure", ignoreCase = true))
    }

    @Test
    fun fromPreference_acceptsKotlinTor() {
        assertEquals(TorEngine.KOTLIN_TOR, TorEngine.fromPreference("KOTLIN_TOR"))
        assertEquals(TorEngine.KOTLIN_TOR, TorEngine.fromPreference("kotlin_tor"))
    }
}
