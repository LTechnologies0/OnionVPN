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
        assertTrue(out.contains("proto tcp4-client"))
        assertFalse(out.contains("proto udp"))
        assertTrue(out.contains("remote vpn.example.com 1194 tcp"))
        assertFalse(out.contains("1194 udp"))
        // Authfile written for docs/probes but NOT on socks-proxy (OpenVPN 2.7 VER=5 bug).
        assertTrue(out.contains("socks-proxy 127.0.0.1 19050\n") || out.contains("socks-proxy 127.0.0.1 19050"))
        assertFalse(out.contains(auth.absolutePath))
        assertFalse(out.contains("socks-proxy-retry"))
        assertTrue(out.contains("server-poll-timeout 120"))
        assertTrue(out.contains("connect-retry 10 120"))
        assertTrue(out.contains("connect-retry-max 12"))
        assertTrue(out.contains("hand-window 120"))
        assertTrue(out.contains("resolv-retry 0"))
        assertTrue(out.contains("auth-retry none"))
        assertTrue(out.contains("persist-remote-ip"))
        assertTrue(out.contains("tun-mtu 1280"))
        assertTrue(out.contains("mssfix 800"))
        assertTrue(out.contains("ping 3"))
        assertTrue(out.contains("ping-restart 180"))
        assertTrue(out.contains("management $mgmt unix"))
        assertTrue(out.contains("management-client"))
        assertTrue(out.contains("management-query-passwords"))
        assertTrue(out.contains("pull-filter ignore \"redirect-gateway\""))
        assertTrue(out.contains("pull-filter ignore \"ping-restart\""))
        assertFalse(out.contains("pull-filter ignore \"ping\""))
        assertTrue(out.contains("route-nopull"))
        assertFalse(out.contains("explicit-exit-notify"))
        assertFalse(out.contains("fragment"))
        assertTrue(auth.readText().contains("uopenvpn"))
        assertTrue(auth.readText().contains("popenvpn"))
        dir.deleteRecursively()
    }

    @Test
    fun rewrite_stripsConflictingTorTimeoutsAndMtu() {
        val dir = File.createTempFile("ovpn-strip", null).apply {
            delete()
            mkdirs()
        }
        val out = OpenVpnConfigWriter.rewrite(
            profileText = """
                client
                proto tcp-client
                remote 203.0.113.1 443 tcp
                tun-mtu 1500
                mssfix 1450
                fragment 1300
                ping 5
                ping-restart 30
                socks-proxy-retry
                connect-retry 1
                server-poll-timeout 10
            """.trimIndent(),
            socksPort = 19050,
            managementSockPath = File(dir, "mgmt.sock").absolutePath,
        )
        assertEquals(1, out.lineSequence().count { it.trimStart().startsWith("tun-mtu ") })
        assertTrue(out.contains("tun-mtu 1280"))
        assertTrue(out.contains("mssfix 800"))
        assertFalse(out.contains("fragment"))
        assertFalse(out.contains("socks-proxy-retry"))
        assertTrue(out.contains("server-poll-timeout 120"))
        assertFalse(out.contains("ping-restart 30"))
        assertTrue(out.contains("ping-restart 180"))
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

    @Test
    fun pinRemoteHostToIpv4_onlyTouchesMatchingHost() {
        val pinned = OpenVpnConfigWriter.pinRemoteHostToIpv4(
            """
                remote a.example.com 443 tcp
                remote b.example.com 443 tcp
            """.trimIndent(),
            "a.example.com",
            "203.0.113.10",
        )
        assertTrue(pinned.contains("remote 203.0.113.10 443 tcp"))
        assertTrue(pinned.contains("remote b.example.com 443 tcp"))
        assertFalse(pinned.contains("a.example.com"))
    }

    @Test
    fun allRemoteHosts_preservesOrderAndDedupes() {
        assertEquals(
            listOf("a.example.com", "1.2.3.4"),
            OpenVpnConfigWriter.allRemoteHosts(
                """
                    remote a.example.com 443
                    remote 1.2.3.4 1194 tcp
                    remote a.example.com 443
                """.trimIndent(),
            ),
        )
    }

    @Test
    fun rewrite_stripsScriptsAndForcesScriptSecurity0() {
        val dir = File.createTempFile("ovpn-script", null).apply {
            delete()
            mkdirs()
        }
        val out = OpenVpnConfigWriter.rewrite(
            profileText = """
                client
                remote 1.2.3.4 443 tcp
                up /tmp/evil.sh
                script-security 2
                verb 1
            """.trimIndent(),
            socksPort = 19050,
            managementSockPath = File(dir, "mgmt.sock").absolutePath,
        )
        assertFalse(out.contains("up /tmp"))
        assertTrue(out.contains("script-security 0"))
        assertTrue(out.contains("verb 3"))
        assertEquals(1, out.lineSequence().count { it.trimStart().startsWith("verb ") })
        dir.deleteRecursively()
    }

    @Test
    fun rewrite_injectsRemoteCertTlsWhenCaPresentWithoutVerify() {
        val dir = File.createTempFile("ovpn-ca", null).apply {
            delete()
            mkdirs()
        }
        val out = OpenVpnConfigWriter.rewrite(
            profileText = """
                client
                remote 203.0.113.1 443 tcp
                <ca>
                -----BEGIN CERTIFICATE-----
                MIIB
                -----END CERTIFICATE-----
                </ca>
            """.trimIndent(),
            socksPort = 19050,
            managementSockPath = File(dir, "mgmt.sock").absolutePath,
        )
        assertTrue(out.contains("<ca>"))
        assertTrue(out.contains("remote-cert-tls server"))
        assertEquals(
            1,
            out.lineSequence().count { it.trimStart().startsWith("remote-cert-tls") },
        )
        dir.deleteRecursively()
    }

    @Test
    fun rewrite_keepsExistingRemoteCertTls() {
        val dir = File.createTempFile("ovpn-verify", null).apply {
            delete()
            mkdirs()
        }
        val out = OpenVpnConfigWriter.rewrite(
            profileText = """
                client
                remote 203.0.113.1 443 tcp
                ca /tmp/ca.crt
                remote-cert-tls server
            """.trimIndent(),
            socksPort = 19050,
            managementSockPath = File(dir, "mgmt.sock").absolutePath,
        )
        assertEquals(
            1,
            out.lineSequence().count { it.trimStart().startsWith("remote-cert-tls") },
        )
        dir.deleteRecursively()
    }

    @Test
    fun rewrite_skipsRemoteCertTlsWithoutCa() {
        val dir = File.createTempFile("ovpn-noca", null).apply {
            delete()
            mkdirs()
        }
        val out = OpenVpnConfigWriter.rewrite(
            profileText = """
                client
                remote 203.0.113.1 443 tcp
            """.trimIndent(),
            socksPort = 19050,
            managementSockPath = File(dir, "mgmt.sock").absolutePath,
        )
        assertFalse(out.contains("remote-cert-tls"))
        dir.deleteRecursively()
    }

    @Test
    fun extractAuthUserPass_readsInlineBlock() {
        val auth = OpenVpnConfigWriter.extractAuthUserPass(
            """
                client
                remote 203.0.113.1 443 tcp
                <auth-user-pass>
                alice
                s3cret!
                </auth-user-pass>
                <ca>
                CERT
                </ca>
            """.trimIndent(),
        )
        assertEquals("alice", auth!!.username)
        assertEquals("s3cret!", auth.password)
    }

    @Test
    fun extractAuthUserPass_inlineUsernameOnly_passwordOptional() {
        val auth = OpenVpnConfigWriter.extractAuthUserPass(
            """
                client
                <auth-user-pass>
                sso-user
                </auth-user-pass>
            """.trimIndent(),
        )
        assertEquals("sso-user", auth!!.username)
        assertEquals("", auth.password)
    }

    @Test
    fun extractAuthUserPass_ignoresCommentedAndBareAuthUserPass() {
        assertEquals(
            null,
            OpenVpnConfigWriter.extractAuthUserPass(
                """
                    client
                    remote 1.2.3.4 443
                    #auth-user-pass
                """.trimIndent(),
            ),
        )
        assertEquals(
            null,
            OpenVpnConfigWriter.extractAuthUserPass(
                """
                    client
                    remote 1.2.3.4 443
                    auth-user-pass
                    <ca>
                    CERT
                    </ca>
                """.trimIndent(),
            ),
        )
    }

    @Test
    fun hasActiveAuthUserPassDirective_detectsBareAndFileForms() {
        assertTrue(
            OpenVpnConfigWriter.hasActiveAuthUserPassDirective("client\nauth-user-pass\n"),
        )
        assertTrue(
            OpenVpnConfigWriter.hasActiveAuthUserPassDirective("auth-user-pass /tmp/up.txt\n"),
        )
        assertFalse(
            OpenVpnConfigWriter.hasActiveAuthUserPassDirective("#auth-user-pass\n"),
        )
    }

    @Test
    fun rewrite_stripsEmbeddedAuthUserPassBlock() {
        val dir = File.createTempFile("ovpn-auth", null).apply {
            delete()
            mkdirs()
        }
        val out = OpenVpnConfigWriter.rewrite(
            profileText = """
                client
                remote 203.0.113.1 443 tcp
                <auth-user-pass>
                bob
                hunter2
                </auth-user-pass>
            """.trimIndent(),
            socksPort = 19050,
            managementSockPath = File(dir, "mgmt.sock").absolutePath,
        )
        assertFalse(out.contains("<auth-user-pass>"))
        assertFalse(out.contains("bob"))
        assertFalse(out.contains("hunter2"))
        dir.deleteRecursively()
    }

    @Test
    fun stripEmbeddedAuthUserPass_preservesOtherBlocks() {
        val cleaned = OpenVpnConfigWriter.stripEmbeddedAuthUserPass(
            """
                client
                <auth-user-pass>
                u
                p
                </auth-user-pass>
                <ca>
                CERT
                </ca>
            """.trimIndent(),
        )
        assertFalse(cleaned.contains("auth-user-pass"))
        assertTrue(cleaned.contains("<ca>"))
        assertTrue(cleaned.contains("CERT"))
    }

    @Test
    fun hasServerTrustMaterial_requiresCaOrPeerPin() {
        assertFalse(
            OpenVpnConfigWriter.hasServerTrustMaterial(
                "client\nremote 203.0.113.1 443 tcp\n",
            ),
        )
        assertFalse(
            OpenVpnConfigWriter.hasServerTrustMaterial(
                "client\nremote-cert-tls server\nremote 203.0.113.1 443 tcp\n",
            ),
        )
        assertTrue(
            OpenVpnConfigWriter.hasServerTrustMaterial(
                """
                client
                remote 203.0.113.1 443 tcp
                <ca>
                CERT
                </ca>
                """.trimIndent(),
            ),
        )
        assertTrue(
            OpenVpnConfigWriter.hasServerTrustMaterial(
                "client\npeer-fingerprint SHA256:aabb\nremote 203.0.113.1 443 tcp\n",
            ),
        )
        assertTrue(
            OpenVpnConfigWriter.hasServerTrustMaterial(
                "client\nverify-x509-name vpn.example.com name\nremote 203.0.113.1 443 tcp\n",
            ),
        )
    }
}
