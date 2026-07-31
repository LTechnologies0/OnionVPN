package ltechnologies.onionphone.onionvpn.core.model.observability

import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class DiagnosticsGateOpTraceTest {
    @Before
    fun resetGate() {
        DiagnosticsGate.onEnabled = null
        DiagnosticsGate.onDisabled = null
        OpTrace.sink = null
        DiagnosticsGate.setNoLogsEnabled(true)
    }

    @Test
    fun noLogsOn_disablesDiagnostics() {
        DiagnosticsGate.setNoLogsEnabled(true)
        assertTrue(DiagnosticsGate.isNoLogs())
        assertFalse(DiagnosticsGate.enabled())
    }

    @Test
    fun noLogsOff_enablesDiagnostics() {
        DiagnosticsGate.setNoLogsEnabled(false)
        assertFalse(DiagnosticsGate.isNoLogs())
        assertTrue(DiagnosticsGate.enabled())
    }

    @Test
    fun opTrace_noopWhenGatedOff() {
        val calls = AtomicInteger(0)
        OpTrace.sink = OpTrace.Sink { _, _, _, _ -> calls.incrementAndGet() }
        DiagnosticsGate.setNoLogsEnabled(true)
        OpTrace.info("test", "should not emit")
        OpTrace.step("test", "step") { 1 }
        assertEquals(0, calls.get())
    }

    @Test
    fun opTrace_emitsWhenEnabled() {
        val calls = AtomicInteger(0)
        OpTrace.sink = OpTrace.Sink { _, _, _, _ -> calls.incrementAndGet() }
        DiagnosticsGate.setNoLogsEnabled(false)
        OpTrace.info("test", "hello")
        assertEquals(1, calls.get())
        OpTrace.step("test", "work") { 42 }
        // start + ok
        assertEquals(3, calls.get())
    }
}
