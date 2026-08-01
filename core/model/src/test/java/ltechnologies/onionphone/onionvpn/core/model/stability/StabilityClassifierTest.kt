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
    fun streamEnd_timeoutIsWarnOnly() {
        val s = StabilityClassifier.forStreamReason("TIMEOUT")
        assertEquals(StabilitySeverity.WARN, s.severity)
        assertEquals(StabilityAction.NONE, s.action)
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
    fun torLog_artiTracingLevels() {
        val warn = StabilityClassifier.forTorLogLine(
            "2026-07-31T15:33:29Z  WARN arti::reload_cfg: Couldn't reload configuration",
        )
        assertEquals(StabilitySeverity.WARN, warn.severity)

        val err = StabilityClassifier.forTorLogLine(
            "AMEx: _configure_and_run_arti_proxy called from wrong state: Stopping",
        )
        assertEquals(StabilitySeverity.ERROR, err.severity)

        val info = StabilityClassifier.forTorLogLine(
            "2026-07-31T15:33:30Z  INFO arti_mobile_ex: Sufficiently bootstrapped; proxy now functional.",
        )
        assertEquals(StabilitySeverity.INFO, info.severity)

        val debug = StabilityClassifier.forTorLogLine(
            "2026-07-31T15:33:30Z  DEBUG tor_circmgr: launching circuit",
        )
        assertEquals(StabilitySeverity.DEBUG, debug.severity)

        val trace = StabilityClassifier.forTorLogLine(
            "2026-07-31T15:33:30Z  TRACE tor_chanmgr: idle",
        )
        assertEquals(StabilitySeverity.TRACE, trace.severity)

        val cTor = StabilityClassifier.forTorLogLine("[notice] Bootstrapped 100% (done)")
        assertEquals(StabilitySeverity.INFO, cTor.severity)
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
