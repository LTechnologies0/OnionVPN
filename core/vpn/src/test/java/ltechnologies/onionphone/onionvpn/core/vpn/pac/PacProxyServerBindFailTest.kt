package ltechnologies.onionphone.onionvpn.core.vpn.pac

import java.net.InetAddress
import java.net.ServerSocket
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PacProxyServerBindFailTest {
    @Test
    fun start_setsRunningFalse_whenSocksBridgePortBusy() {
        ServerSocket(
            TunnelEndpoints.PAC_BRIDGE_SOCKS_PORT,
            1,
            InetAddress.getByName(TunnelEndpoints.LOOPBACK),
        ).use {
            val pac = PacProxyServer()
            var threw = false
            try {
                pac.start()
            } catch (_: Exception) {
                threw = true
            }
            assertTrue("bind fail must throw", threw)
            assertFalse("running must be false after socksBridge.start() fail", pac.isRunning)
        }
    }
}
