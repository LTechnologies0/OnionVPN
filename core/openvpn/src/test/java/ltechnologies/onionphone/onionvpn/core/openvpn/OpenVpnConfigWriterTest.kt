package ltechnologies.onionphone.onionvpn.core.openvpn

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OpenVpnConfigWriterTest {
    @Test
    fun rewrite_forcesTcpSocksAndUnixManagement() {
        val dir = File.createTempFile("ovpn-test", null).apply {
            delete()
            mkdirs()
        }
        val auth = File(dir, "auth.txt")
        val mgmt = File(dir, "mgmt.sock").absolutePath
        val out = OpenVpnConfigWriter.rewrite(
            profileText = """
                client
                proto udp
                remote vpn.example.com 1194 udp
                socks-proxy 1.2.3.4 1080
                explicit-exit-notify 1
            """.trimIndent(),
            socksPort = 19050,
            managementSockPath = mgmt,
            socksAuthFile = auth,
        )
        assertTrue(out.contains("proto tcp-client"))
        assertFalse(out.contains("proto udp"))
        assertTrue(out.contains("remote vpn.example.com 1194 tcp"))
        assertFalse(out.contains("1194 udp"))
        assertTrue(out.contains("socks-proxy 127.0.0.1 19050"))
        assertTrue(out.contains(auth.absolutePath))
        assertTrue(out.contains("management $mgmt unix"))
        assertTrue(out.contains("management-client"))
        assertTrue(out.contains("pull-filter ignore \"redirect-gateway\""))
        assertTrue(out.contains("route-nopull"))
        assertFalse(out.contains("explicit-exit-notify"))
        assertTrue(auth.readText().contains("openvpn"))
        dir.deleteRecursively()
    }

    @Test
    fun pinRemoteToIpv4_rewritesHostAndForcesTcp() {
        val pinned = OpenVpnConfigWriter.pinRemoteToIpv4(
            """
                client
                remote vpn.example.com 443 udp
                remote-random
            """.trimIndent(),
            "203.0.113.10",
        )
        assertTrue(pinned.contains("remote 203.0.113.10 443 tcp"))
        assertFalse(pinned.contains("vpn.example.com"))
        assertFalse(pinned.contains("udp"))
        assertEquals(
            "vpn.example.com",
            OpenVpnConfigWriter.firstRemoteHost("remote vpn.example.com 1194\n"),
        )
    }

    @Test
    fun looksUdpOnly_detectsUdpProfiles() {
        assertTrue(
            OpenVpnConfigWriter.looksUdpOnly(
                """
                    client
                    proto udp
                    remote 1.2.3.4 1194
                """.trimIndent(),
            ),
        )
        assertFalse(
            OpenVpnConfigWriter.looksUdpOnly(
                """
                    client
                    proto tcp-client
                    remote 1.2.3.4 443
                """.trimIndent(),
            ),
        )
        assertFalse(
            OpenVpnConfigWriter.looksUdpOnly(
                """
                    client
                    proto udp
                    remote 1.2.3.4 443 tcp
                """.trimIndent(),
            ),
        )
    }
}
