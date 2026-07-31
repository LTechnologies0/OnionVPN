package ltechnologies.onionphone.onionvpn.core.tor.control

import ltechnologies.onionphone.onionvpn.core.model.TorEngine
import ltechnologies.onionphone.onionvpn.core.tor.control.TorControlCompat.ArtiBehavior
import ltechnologies.onionphone.onionvpn.core.tor.control.TorControlCompat.Parity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TorControlCompatTest {

    @Test
    fun docsVersion_isArtiClient036() {
        assertEquals("0.36.0", TorControlCompat.ARTI_CLIENT_DOCS_VERSION)
        assertTrue(TorControlCompat.ARTI_CLIENT_DOCS_URL.contains("0.36.0"))
    }

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
    fun arti_semanticOneToOneOps() {
        val oneToOne = listOf(
            "NEWNYM",
            "RELOAD",
            "SHUTDOWN",
            "DROPTIMEOUTS",
            "DROPGUARDS",
            "DisableNetwork",
            "SETCONF_bridges",
            "CLOSE_BUILT_CIRCUITS",
            "CLEARDNSCACHE",
            "RESOLVE",
            "GETINFO_bootstrap",
            "GETINFO_traffic",
            "ACTIVE",
            "DORMANT",
            "HEARTBEAT",
            "SOCKS_AUTH_ISOLATION",
        )
        for (name in oneToOne) {
            assertTrue(name, TorControlCompat.isOneToOneOnArti(name))
            assertTrue(name, TorControlCompat.isSupported(TorEngine.ARTI, name))
        }
        assertEquals(Parity.SEMANTIC_1_1, TorControlCompat.parity("NEWNYM"))
        assertEquals(ArtiBehavior.EQUIVALENT, TorControlCompat.behavior("NEWNYM"))
        assertEquals(ArtiBehavior.HARD_RECOVER, TorControlCompat.behavior("RELOAD"))
        assertEquals(ArtiBehavior.EQUIVALENT, TorControlCompat.behavior("RESOLVE"))
        assertEquals(Parity.APP_LAYER_1_1, TorControlCompat.parity("RESOLVE"))
        assertEquals(Parity.APP_LAYER_1_1, TorControlCompat.parity("CLEARDNSCACHE"))
        assertEquals(Parity.APP_LAYER_1_1, TorControlCompat.parity("ACTIVE"))
        assertEquals(Parity.APP_LAYER_1_1, TorControlCompat.parity("DORMANT"))
        assertEquals(ArtiBehavior.EQUIVALENT, TorControlCompat.behavior("ACTIVE"))
        assertEquals(ArtiBehavior.EQUIVALENT, TorControlCompat.behavior("DORMANT"))
        assertEquals(ArtiBehavior.EQUIVALENT, TorControlCompat.behavior("SOCKS_AUTH_ISOLATION"))
    }

    @Test
    fun arti_engineLimitations_areGated() {
        val limited = listOf(
            "GETINFO_circuits",
            "GETINFO_streams",
            "EXTENDCIRCUIT",
            "CLOSECIRCUIT",
            "CLOSESTREAM",
            "SETEVENTS",
            "AUTHENTICATE",
            "SETCONF_geoip",
            "SETCONF_nodes",
            "SETCONF_circuit_timing",
        )
        for (name in limited) {
            assertEquals(name, Parity.ENGINE_LIMITATION, TorControlCompat.parity(name))
            assertFalse("isOneToOne $name", TorControlCompat.isOneToOneOnArti(name))
        }
        for (name in listOf(
            "GETINFO_circuits", "EXTENDCIRCUIT", "CLOSECIRCUIT", "SETCONF_nodes", "SETCONF_geoip",
        )) {
            assertFalse(name, TorControlCompat.isSupported(TorEngine.ARTI, name))
        }
        assertEquals(ArtiBehavior.NOOP_OK, TorControlCompat.behavior("SETCONF_circuit_timing"))
        assertTrue(TorControlCompat.isSupported(TorEngine.ARTI, "SETCONF_circuit_timing"))
    }

    @Test
    fun arti_softAndHardRecover() {
        assertEquals(ArtiBehavior.SOFT_RECOVER, TorControlCompat.behavior("CLEARDNSCACHE"))
        assertEquals(ArtiBehavior.SOFT_RECOVER, TorControlCompat.behavior("DROPTIMEOUTS"))
        assertEquals(ArtiBehavior.HARD_RECOVER, TorControlCompat.behavior("DROPGUARDS"))
        assertEquals(ArtiBehavior.HARD_RECOVER, TorControlCompat.behavior("DisableNetwork"))
        assertEquals(ArtiBehavior.REQUIRES_RESTART, TorControlCompat.behavior("SETCONF_bridges"))
    }

    @Test
    fun everyOpCitesArtiClient036OrControlSpec() {
        for (op in TorControlCompat.OPS) {
            assertTrue(op.name, op.docs.isNotBlank())
            assertTrue(op.name, op.artiImpl.isNotBlank())
            assertTrue(op.name, op.littleT.isNotBlank())
        }
        // Core mappings must cite 0.36.0 APIs we verified on docs.rs
        assertTrue(TorControlCompat.OPS.first { it.name == "NEWNYM" }.docs.contains("isolated_client"))
        assertTrue(TorControlCompat.OPS.first { it.name == "DORMANT" }.docs.contains("set_dormant"))
        assertTrue(TorControlCompat.OPS.first { it.name == "RESOLVE" }.docs.contains("resolve"))
        assertTrue(
            TorControlCompat.OPS.first { it.name == "SETCONF_circuit_timing" }.docs
                .contains("max_dirtiness"),
        )
        assertTrue(
            TorControlCompat.OPS.first { it.name == "GETINFO_bootstrap" }.docs
                .contains("ready_for_traffic"),
        )
    }

    @Test
    fun matrixCoversCriticalOnionVpnOps() {
        val names = TorControlCompat.OPS.map { it.name }.toSet()
        assertTrue(
            names.containsAll(
                listOf(
                    "NEWNYM", "CLEARDNSCACHE", "ACTIVE", "DORMANT", "RELOAD",
                    "DROPTIMEOUTS", "DROPGUARDS", "DisableNetwork",
                    "SETCONF_circuit_timing", "SETCONF_bridges", "SETCONF_nodes",
                    "GETINFO_bootstrap", "GETINFO_circuits", "GETINFO_traffic",
                    "EXTENDCIRCUIT", "CLOSECIRCUIT", "RESOLVE", "CLOSE_BUILT_CIRCUITS",
                    "SOCKS_AUTH_ISOLATION",
                ),
            ),
        )
    }

    @Test
    fun unknownOp_isUnsupportedOnArti() {
        assertEquals(ArtiBehavior.UNSUPPORTED, TorControlCompat.behavior("NOT_A_REAL_OP"))
        assertFalse(TorControlCompat.isSupported(TorEngine.ARTI, "NOT_A_REAL_OP"))
        assertEquals(Parity.ENGINE_LIMITATION, TorControlCompat.parity("NOT_A_REAL_OP"))
        assertTrue(TorControlCompat.unsupportedMessage("CLOSECIRCUIT").contains("0.36.0"))
    }
}
