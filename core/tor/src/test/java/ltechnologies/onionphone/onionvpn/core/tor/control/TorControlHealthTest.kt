package ltechnologies.onionphone.onionvpn.core.tor.control

import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlEvent
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TorControlHealthTest {
    @Test
    fun disconnected_failsWhenRequired() {
        val check = TorControlHealth.validate(TorControlStatus(), requireConnected = true)
        assertEquals(ValidationStatus.Fail, check.status)
        assertTrue(check.tripsKillSwitch)
    }

    @Test
    fun bootstrapped_passes() {
        val check = TorControlHealth.validate(
            TorControlStatus(
                connected = true,
                bootstrapProgress = 100,
                circuitEstablished = true,
                enoughDirInfo = true,
                builtCircuits = 2,
                torVersion = "0.4.8.0",
            ),
        )
        assertEquals(ValidationStatus.Pass, check.status)
        assertTrue(check.detail.contains("boot=100%"))
    }
}

class TorControlEventFormatterTest {
    @Test
    fun formatsBootstrap() {
        val line = TorControlEventFormatter.format(
            TorControlEvent.Bootstrap(100, "done", "Done"),
        )
        assertTrue(line.contains("BOOTSTRAP 100%"))
        assertTrue(line.contains("done"))
    }

    @Test
    fun formatsCircuit() {
        val line = TorControlEventFormatter.format(
            TorControlEvent.Circuit("3", "BUILT", "a,b,c"),
        )
        assertEquals("CTRL CIRC BUILT 3 a,b,c", line)
    }
}
