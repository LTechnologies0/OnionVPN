package ltechnologies.onionphone.onionvpn.core.tor.control.catalog

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TorControlCatalogTest {
    @Test
    fun clientEvents_includesCoreVpnSet() {
        val events = TorControlCatalog.CLIENT_EVENTS
        listOf(
            "STATUS_CLIENT",
            "CIRC",
            "STREAM",
            "ORCONN",
            "BW",
            "ADDRMAP",
            "NOTICE",
            "WARN",
            "ERR",
            "GUARD",
        ).forEach { name ->
            assertTrue("$name missing from CLIENT_EVENTS", events.contains(name))
        }
        assertFalse(events.contains("DROPTIMEOUTS"))
    }

    @Test
    fun signals_includeNetworkLifecycle() {
        val wires = TorControlCatalog.Signal.entries.map { it.wire }.toSet()
        assertTrue(wires.containsAll(listOf("NEWNYM", "ACTIVE", "DORMANT", "CLEARDNSCACHE", "HEARTBEAT")))
    }

    @Test
    fun commands_includeNativeVpnSurface() {
        val wires = TorControlCatalog.Command.entries.map { it.wire }.toSet()
        assertTrue(
            wires.containsAll(
                listOf(
                    "GETINFO",
                    "SIGNAL",
                    "SETEVENTS",
                    "TAKEOWNERSHIP",
                    "RESOLVE",
                    "DROPGUARDS",
                    "DROPTIMEOUTS",
                    "SETCONF",
                    "CLOSECIRCUIT",
                ),
            ),
        )
    }

    @Test
    fun healthGetInfo_coversBootstrapAndGuards() {
        assertTrue(TorControlCatalog.HEALTH_GETINFO_KEYS.contains("status/bootstrap-phase"))
        assertTrue(TorControlCatalog.HEALTH_GETINFO_KEYS.contains("entry-guards"))
        assertTrue(TorControlCatalog.HEALTH_GETINFO_KEYS.contains("network-liveness"))
    }
}
