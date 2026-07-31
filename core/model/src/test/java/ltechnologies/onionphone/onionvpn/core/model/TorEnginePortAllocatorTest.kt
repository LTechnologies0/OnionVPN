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
    fun arti_sharesSingleSocksPortAcrossRoles() {
        val ports = TunnelPortAllocator.allocate(TorEngine.ARTI)
        assertEquals(ports.torSocksPort, ports.torDnsCryptSocksPort)
        assertEquals(ports.torSocksPort, ports.torProbeSocksPort)
        assertNotEquals(ports.torSocksPort, ports.torDnsPort)
        assertTrue(ports.dnsCryptListenPort > 0)
    }

    @Test
    fun fromPreference_defaultsToLittleT() {
        assertEquals(TorEngine.LITTLE_T, TorEngine.fromPreference(null))
        assertEquals(TorEngine.LITTLE_T, TorEngine.fromPreference("nope"))
        assertEquals(TorEngine.ARTI, TorEngine.fromPreference("arti"))
        assertEquals(TorEngine.LITTLE_T, TorEngine.fromPreference("LITTLE_T"))
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
        assertFalse(a.circuitInspection)
        assertFalse(a.conjureBridges)
        assertFalse(a.nodePrefs)
        assertTrue(a.bridgesAtStart)
        assertTrue(a.socksAuthIsolation)
        assertTrue(a.dormantSignals) // TorClient::set_dormant via Ext JNI when patched
        assertTrue(c.nodePrefs)
        assertTrue(c.bridgesAtStart)
        assertTrue(c.socksAuthIsolation)
        assertTrue(c.dormantSignals)
    }
}
