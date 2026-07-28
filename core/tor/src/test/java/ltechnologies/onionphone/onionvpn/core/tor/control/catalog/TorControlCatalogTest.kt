package ltechnologies.onionphone.onionvpn.core.tor.control.catalog

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TorControlCatalogTest {
    @Test
    fun clientEvents_coreIsTightOrbotSet() {
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
        assertFalse("PT events must not be in core SETEVENTS", events.contains("PT_LOG"))
        assertFalse(events.contains("TRANSPORT_LAUNCHED"))
        assertFalse(events.contains("CIRC_MINOR"))
        assertFalse(events.contains("DROPTIMEOUTS"))
    }

    @Test
    fun eventTiers_areDisjoint() {
        val core = TorControlCatalog.CLIENT_EVENTS.split(' ').toSet()
        val optional = TorControlCatalog.CLIENT_EVENTS_OPTIONAL.split(' ').toSet()
        val pt = TorControlCatalog.CLIENT_EVENTS_PT.split(' ').toSet()
        assertTrue(core.intersect(optional).isEmpty())
        assertTrue(core.intersect(pt).isEmpty())
        assertTrue(optional.intersect(pt).isEmpty())
        assertTrue(pt.containsAll(listOf("TRANSPORT_LAUNCHED", "PT_LOG", "PT_STATUS")))
        assertTrue(optional.contains("CIRC_MINOR"))
    }

    @Test
    fun healthGetInfo_tiersDoNotOverlapAndDropUnused() {
        val core = TorControlCatalog.HEALTH_GETINFO_CORE.toSet()
        val optional = TorControlCatalog.HEALTH_GETINFO_OPTIONAL.toSet()
        val traffic = TorControlCatalog.HEALTH_GETINFO_TRAFFIC.toSet()
        val heavy = TorControlCatalog.HEALTH_GETINFO_HEAVY.toSet()
        assertTrue(core.contains("status/bootstrap-phase"))
        assertTrue(optional.containsAll(listOf("dormant", "network-liveness")))
        assertTrue(heavy.contains("entry-guards"))
        assertFalse(TorControlCatalog.HEALTH_GETINFO_KEYS.contains("process/pid"))
        assertFalse(TorControlCatalog.HEALTH_GETINFO_KEYS.contains("status/good-server-descriptor"))
        assertEquals(
            core.size + optional.size + traffic.size + heavy.size,
            TorControlCatalog.HEALTH_GETINFO_KEYS.size,
        )
        assertTrue(core.intersect(optional).isEmpty())
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
                    "USEFEATURE",
                ),
            ),
        )
    }
}
