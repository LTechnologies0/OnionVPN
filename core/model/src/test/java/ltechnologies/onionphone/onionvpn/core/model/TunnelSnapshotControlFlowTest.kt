package ltechnologies.onionphone.onionvpn.core.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelSnapshotControlFlowTest {
    @Test
    fun canStart_onlyIdleErrorBlocking() {
        assertTrue(TunnelSnapshot(phase = TunnelPhase.Idle).canStart)
        assertTrue(TunnelSnapshot(phase = TunnelPhase.Error).canStart)
        assertTrue(TunnelSnapshot(phase = TunnelPhase.Blocking).canStart)
        assertFalse(TunnelSnapshot(phase = TunnelPhase.Connected).canStart)
        assertFalse(TunnelSnapshot(phase = TunnelPhase.StartingTor).canStart)
        assertFalse(TunnelSnapshot(phase = TunnelPhase.Validating).canStart)
        assertFalse(TunnelSnapshot(phase = TunnelPhase.Stopping).canStart)
    }

    @Test
    fun canStop_blocksIdleStoppingError() {
        assertFalse(TunnelSnapshot(phase = TunnelPhase.Idle).canStop)
        assertFalse(TunnelSnapshot(phase = TunnelPhase.Stopping).canStop)
        assertFalse(TunnelSnapshot(phase = TunnelPhase.Error).canStop)
        assertTrue(TunnelSnapshot(phase = TunnelPhase.Connected).canStop)
        assertTrue(TunnelSnapshot(phase = TunnelPhase.StartingTor).canStop)
        assertTrue(TunnelSnapshot(phase = TunnelPhase.Blocking).canStop)
    }

    @Test
    fun canNewNym_requiresConnectedReadyNotRefreshing() {
        assertFalse(TunnelSnapshot(phase = TunnelPhase.Connected).canNewNym)
        assertTrue(
            TunnelSnapshot(
                phase = TunnelPhase.Connected,
                torRuntimeReady = true,
            ).canNewNym,
        )
        assertFalse(
            TunnelSnapshot(
                phase = TunnelPhase.Connected,
                torRuntimeReady = true,
                identityRefreshing = true,
            ).canNewNym,
        )
        assertFalse(
            TunnelSnapshot(
                phase = TunnelPhase.Connected,
                torRuntimeReady = true,
                newNymCooldownUntilMs = System.currentTimeMillis() + 60_000L,
            ).canNewNym,
        )
    }
}
