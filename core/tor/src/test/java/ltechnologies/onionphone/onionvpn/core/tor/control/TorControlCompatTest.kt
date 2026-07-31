package ltechnologies.onionphone.onionvpn.core.tor.control

import ltechnologies.onionphone.onionvpn.core.model.TorEngine
import ltechnologies.onionphone.onionvpn.core.tor.control.TorControlCompat.ArtiBehavior
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TorControlCompatTest {

    @Test
    fun littleT_supportsEveryOp() {
        for (op in TorControlCompat.OPS) {
            assertTrue(
                "C Tor must support ${op.name}",
                TorControlCompat.isSupported(TorEngine.LITTLE_T, op.name),
            )
        }
    }

    @Test
    fun arti_newNymIsEquivalent() {
        assertEquals(ArtiBehavior.EQUIVALENT, TorControlCompat.behavior("NEWNYM"))
        assertTrue(TorControlCompat.isSupported(TorEngine.ARTI, "NEWNYM"))
    }

    @Test
    fun arti_softRecoverOps() {
        assertEquals(ArtiBehavior.SOFT_RECOVER, TorControlCompat.behavior("CLEARDNSCACHE"))
        assertEquals(ArtiBehavior.SOFT_RECOVER, TorControlCompat.behavior("DROPTIMEOUTS"))
        assertTrue(TorControlCompat.isSupported(TorEngine.ARTI, "CLEARDNSCACHE"))
        assertTrue(TorControlCompat.isSupported(TorEngine.ARTI, "DROPTIMEOUTS"))
    }

    @Test
    fun arti_hardRecoverOps() {
        assertEquals(ArtiBehavior.HARD_RECOVER, TorControlCompat.behavior("DROPGUARDS"))
        assertEquals(ArtiBehavior.HARD_RECOVER, TorControlCompat.behavior("DisableNetwork"))
    }

    @Test
    fun arti_noopOkOps() {
        assertEquals(ArtiBehavior.NOOP_OK, TorControlCompat.behavior("ACTIVE"))
        assertEquals(ArtiBehavior.NOOP_OK, TorControlCompat.behavior("DORMANT"))
        assertEquals(ArtiBehavior.NOOP_OK, TorControlCompat.behavior("HEARTBEAT"))
        assertEquals(ArtiBehavior.NOOP_OK, TorControlCompat.behavior("SETCONF_circuit_timing"))
    }

    @Test
    fun arti_requiresRestartOps() {
        assertEquals(ArtiBehavior.REQUIRES_RESTART, TorControlCompat.behavior("RELOAD"))
        assertEquals(ArtiBehavior.REQUIRES_RESTART, TorControlCompat.behavior("SETCONF_bridges"))
        assertEquals(ArtiBehavior.REQUIRES_RESTART, TorControlCompat.behavior("SETCONF_nodes"))
        assertTrue(TorControlCompat.isSupported(TorEngine.ARTI, "SETCONF_bridges"))
    }

    @Test
    fun arti_unsupportedCircuitPlane() {
        val unsupported = listOf(
            "GETINFO_circuits",
            "GETINFO_streams",
            "GETINFO_traffic",
            "EXTENDCIRCUIT",
            "CLOSECIRCUIT",
            "CLOSESTREAM",
            "RESOLVE",
            "SETEVENTS",
            "AUTHENTICATE",
            "SETCONF_geoip",
        )
        for (name in unsupported) {
            assertEquals(name, ArtiBehavior.UNSUPPORTED, TorControlCompat.behavior(name))
            assertFalse(name, TorControlCompat.isSupported(TorEngine.ARTI, name))
        }
    }

    @Test
    fun arti_bootstrapIsEquivalent() {
        assertEquals(ArtiBehavior.EQUIVALENT, TorControlCompat.behavior("GETINFO_bootstrap"))
        assertEquals(ArtiBehavior.EQUIVALENT, TorControlCompat.behavior("SHUTDOWN"))
    }

    @Test
    fun unknownOp_isUnsupportedOnArti() {
        assertEquals(ArtiBehavior.UNSUPPORTED, TorControlCompat.behavior("NOT_A_REAL_OP"))
        assertFalse(TorControlCompat.isSupported(TorEngine.ARTI, "NOT_A_REAL_OP"))
        assertTrue(
            TorControlCompat.unsupportedMessage("CLOSECIRCUIT").contains("Arti"),
        )
    }

    @Test
    fun matrixCoversCriticalOnionVpnOps() {
        val names = TorControlCompat.OPS.map { it.name }.toSet()
        // Every ControlPort family OnionVPN actually uses must be listed.
        assertTrue(names.containsAll(
            listOf(
                "NEWNYM", "CLEARDNSCACHE", "ACTIVE", "DORMANT", "RELOAD",
                "DROPTIMEOUTS", "DROPGUARDS", "DisableNetwork",
                "SETCONF_circuit_timing", "SETCONF_bridges", "SETCONF_nodes",
                "GETINFO_bootstrap", "GETINFO_circuits", "EXTENDCIRCUIT", "CLOSECIRCUIT",
            ),
        ))
    }
}
