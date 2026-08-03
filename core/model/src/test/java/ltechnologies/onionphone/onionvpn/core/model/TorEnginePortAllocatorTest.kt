package ltechnologies.onionphone.onionvpn.core.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TorEnginePortAllocatorTest {
    @Test
    fun littleT_allocatesDistinctSocksPorts() {
        val ports = TunnelPortAllocator.allocate(TorEngine.LITTLE_T)
        assertNotEquals(ports.torSocksPort, ports.torDnsCryptSocksPort)
        assertNotEquals(ports.torSocksPort, ports.torProbeSocksPort)
        assertNotEquals(ports.torDnsCryptSocksPort, ports.torProbeSocksPort)
        assertNotEquals(ports.torSocksPort, ports.torDnsPort)
    }

    @Test
    fun arti_allocatesDistinctRoleSocksPorts() {
        // Distinct listen ports; ArtiSocksRoleMux relays DNSCrypt/probe → Arti SOCKS.
        val ports = TunnelPortAllocator.allocate(TorEngine.ARTI)
        assertNotEquals(ports.torSocksPort, ports.torDnsCryptSocksPort)
        assertNotEquals(ports.torSocksPort, ports.torProbeSocksPort)
        assertNotEquals(ports.torDnsCryptSocksPort, ports.torProbeSocksPort)
        assertNotEquals(ports.torSocksPort, ports.torDnsPort)
        assertTrue(ports.dnsCryptListenPort > 0)
    }

    @Test
    fun fromPreference_defaultsToLittleT() {
        assertEquals(TorEngine.LITTLE_T, TorEngine.fromPreference(null))
        assertEquals(TorEngine.LITTLE_T, TorEngine.fromPreference("nope"))
        assertEquals(TorEngine.ARTI, TorEngine.fromPreference("arti"))
        assertEquals(TorEngine.LITTLE_T, TorEngine.fromPreference("LITTLE_T"))
        // Former kotlin-tor prefs migrate to C Tor.
        assertEquals(TorEngine.LITTLE_T, TorEngine.fromPreference("KOTLIN_TOR"))
        assertEquals(TorEngine.LITTLE_T, TorEngine.fromPreference("kotlin_tor"))
    }

    @Test
    fun capabilities_differByEngine() {
        val c = TorEngine.LITTLE_T.capabilities
        val a = TorEngine.ARTI.capabilities
        assertTrue(c.classicControlPlane && c.torrcConfig && c.multiSocksSessionGroups)
        assertFalse(a.classicControlPlane)
        assertFalse(a.torrcConfig)
        assertTrue(a.synthesizeOnionAutomap)
        assertTrue(a.newIdentity)
        assertTrue(a.circuitInspection)
        assertTrue(a.conjureBridges)
        assertFalse(a.nodePrefs)
        assertTrue(a.exitCountryPrefs)
        assertTrue(a.liveCircuitTiming)
        assertTrue(a.bridgesAtStart)
        assertTrue(a.socksAuthIsolation)
        assertTrue(a.multiSocksSessionGroups) // app-layer role relays
        assertTrue(a.dormantSignals) // TorClient::set_dormant via Ext JNI when patched
        assertTrue(c.nodePrefs)
        assertTrue(c.exitCountryPrefs)
        assertTrue(c.liveCircuitTiming)
        assertTrue(c.bridgesAtStart)
        assertTrue(c.socksAuthIsolation)
        assertTrue(c.dormantSignals)
    }
}
