package ltechnologies.onionphone.onionvpn.core.vpn.pac

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PacScriptTest {
    @Test
    fun live_pointsAtDnsCryptBridge_notRawTor() {
        val pac = PacScript.build(bridgeUp = true)
        assertTrue(pac.contains("SOCKS5 127.0.0.1:${TunnelEndpoints.PAC_BRIDGE_SOCKS_PORT}"))
        assertTrue(pac.contains("DNSCrypt"))
        assertFalse(pac.contains("HTTPTunnelPort"))
        assertFalse(pac.contains("dnsResolve("))
    }

    @Test
    fun down_failClosed() {
        val pac = PacScript.build(bridgeUp = false)
        assertTrue(pac.contains("PROXY 127.0.0.1:1"))
    }
}
