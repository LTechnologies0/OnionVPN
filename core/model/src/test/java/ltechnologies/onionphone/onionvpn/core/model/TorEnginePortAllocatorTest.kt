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
    fun kotlinTor_allocatesDistinctSocksPortsLikeLittleT() {
        // Same HEV_SOCKS role ports as little-t (apps / DNSCrypt / probe / DNSPort).
        val ports = TunnelPortAllocator.allocate(TorEngine.KOTLIN_TOR)
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
        assertEquals(TorEngine.KOTLIN_TOR, TorEngine.fromPreference("KOTLIN_TOR"))
    }

    @Test
    fun capabilities_differByEngine() {
        val c = TorEngine.LITTLE_T.capabilities
        val a = TorEngine.ARTI.capabilities
        val k = TorEngine.KOTLIN_TOR.capabilities
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
        // KOTLIN_TOR mirrors little-t HEV_SOCKS flags; no torrc/Conjure yet.
        assertTrue(k.classicControlPlane)
        assertTrue(k.multiSocksSessionGroups)
        assertTrue(k.socksAuthIsolation)
        assertTrue(k.nativeAutomapDnsPort)
        assertFalse(k.synthesizeOnionAutomap)
        assertTrue(k.newIdentity)
        assertFalse(k.torrcConfig)
        assertFalse(k.conjureBridges)
        assertFalse(k.liveSetConf)
    }
}
