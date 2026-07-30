package ltechnologies.onionphone.onionvpn.core.model.stability

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class StabilityClassifierTest {
    @Test
    fun streamEnd_doneIsIgnored() {
        val s = StabilityClassifier.forStreamReason("DONE")
        assertEquals(StabilitySeverity.IGNORE, s.severity)
        assertEquals(StabilityAction.NONE, s.action)
        assertEquals("6", TorStabilityCodes.StreamEnd.DONE.code.toString())
    }

    @Test
    fun streamEnd_norouteSoftRecover() {
        val s = StabilityClassifier.forStreamReason("NOROUTE")
        assertEquals(StabilityAction.SOFT_RECOVER, s.action)
        assertEquals(
            StabilityAction.SOFT_RECOVER,
            StabilityClassifier.forStreamReason("8").action,
        )
    }

    @Test
    fun circ_nopathAndOrConnNoroute() {
        assertEquals(
            StabilityAction.SOFT_RECOVER,
            StabilityClassifier.forCircReason("NOPATH").action,
        )
        assertEquals(
            StabilityAction.HARD_RECOVER,
            StabilityClassifier.forOrConnReason("NOROUTE").action,
        )
    }

    @Test
    fun socks_rfcAndOnionExtensions() {
        assertEquals(StabilitySeverity.IGNORE, StabilityClassifier.forSocksStatus(0x00).severity)
        assertEquals(
            StabilityAction.SOFT_RECOVER,
            StabilityClassifier.forSocksStatus(0x03).action,
        )
        assertTrue(
            StabilityClassifier.forSocksStatus(0xF0).detail.contains("onion", ignoreCase = true),
        )
        assertEquals(
            StabilityAction.SOFT_RECOVER,
            StabilityClassifier.forSocksStatus(0xF7).action,
        )
    }

    @Test
    fun dnscrypt_criticalVsProbeNoise() {
        assertTrue(
            StabilityClassifier.forDnsCryptLog("[CRITICAL] no servers available").isError,
        )
        assertFalse(
            StabilityClassifier.forDnsCryptLog("[DEBUG] probe timeout waiting").isError,
        )
    }

    @Test
    fun torLog_bootstrapProblem() {
        val s = StabilityClassifier.forTorLogLine("[warn] Problem bootstrapping: connection refused")
        assertTrue(s.isWarnOrWorse)
    }

    @Test
    fun mergeAction_prefersStopTor() {
        assertEquals(
            StabilityAction.STOP_TOR,
            StabilityClassifier.mergeAction(
                StabilitySignal("a", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
                StabilitySignal("b", StabilitySeverity.CRITICAL, StabilityAction.STOP_TOR),
                StabilitySignal("c", StabilitySeverity.ERROR, StabilityAction.PREFER_BLOCKING),
            ),
        )
    }
}
