package ltechnologies.onionphone.onionvpn.core.dnscrypt.config

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

@RunWith(Parameterized::class)
class AntiLeakDnsCryptTest(private val requiredSubstring: String) {
    @Test
    fun configContainsRequiredAntiLeakKey() {
        val config = DnsCryptConfigWriter.write(
            configDirectory = "/tmp",
            preferences = TunnelPreferences(dnsCryptForceTcp = false), // must still force true
        )
        assertTrue(
            "Missing DNSCrypt anti-leak key: $requiredSubstring\n---\n$config",
            config.contains(requiredSubstring),
        )
    }

    companion object {
        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun keys(): List<Array<String>> = listOf(
            "force_tcp = true",
            "ignore_system_dns = true",
            "dnscrypt_ephemeral_keys = true",
            "tls_disable_session_tickets = true",
            "block_ipv6 = true",
            "ipv6_servers = false",
            "ipv4_servers = true",
            "proxy = 'socks5://${TunnelEndpoints.SOCKS_DNSCRYPT_USER}:${TunnelEndpoints.SOCKS_DNSCRYPT_PASS}",
            "bootstrap_resolvers = ['${TunnelEndpoints.LOOPBACK}:",
            "netprobe_address = '${TunnelEndpoints.LOOPBACK}:",
            "listen_addresses = ['${TunnelEndpoints.LOOPBACK}:",
            "[blocked_names]",
            "[sources.'public-resolvers']",
            "minisign_key",
            "cache = true",
            "timeout = 25000",
        ).map { arrayOf(it) }
    }
}

@RunWith(Parameterized::class)
class AntiLeakDnsCryptBlockedNamesTest(private val host: String) {
    @Test
    fun blockedNamesIncludesHost() {
        val body = DnsCryptConfigWriter.blockedNamesFileContent()
        assertTrue("blocked_names missing $host", body.lineSequence().any { it.trim() == host })
    }

    companion object {
        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun hosts(): List<Array<String>> =
            DnsCryptConfigWriter.blockedNamesFileContent()
                .lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .map { arrayOf(it) }
                .toList()
    }
}

class AntiLeakDnsCryptAppHostsNotBlockedTest {
    @Test
    fun googlePlayAndFcmHostsAreNotBlocked() {
        val body = DnsCryptConfigWriter.blockedNamesFileContent()
        val mustStayResolvable = listOf(
            "android.googleapis.com",
            "play.googleapis.com",
            "mtalk.google.com",
            "chat.signal.org",
            "api.twitter.com",
            "www.gstatic.com",
            "clients3.google.com",
        )
        for (host in mustStayResolvable) {
            assertFalse(
                "Must not block app-critical host: $host",
                body.lineSequence().any { it.trim() == host },
            )
        }
    }
}

class AntiLeakDnsCryptForceTcpOverrideTest {
    @Test
    fun forceTcpAlwaysTrueEvenWhenPrefFalse() {
        val config = DnsCryptConfigWriter.write(
            configDirectory = "/tmp",
            preferences = TunnelPreferences(dnsCryptForceTcp = false),
        )
        assertTrue(config.contains("force_tcp = true"))
        assertFalse(config.contains("force_tcp = false"))
    }
}
