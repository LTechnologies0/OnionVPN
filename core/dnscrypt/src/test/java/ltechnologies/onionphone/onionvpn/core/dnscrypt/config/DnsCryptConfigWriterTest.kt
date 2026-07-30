package ltechnologies.onionphone.onionvpn.core.dnscrypt.config

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsCryptConfigWriterTest {
    @Test
    fun forcesUpstreamThroughTorAndBootstrapThroughDnsPort() {
        val config = DnsCryptConfigWriter.write(configDirectory = "/tmp")

        val proxy =
            "socks5://${TunnelEndpoints.SOCKS_DNSCRYPT_USER}:${TunnelEndpoints.SOCKS_DNSCRYPT_PASS}" +
                "@${TunnelEndpoints.LOOPBACK}:${TunnelEndpoints.TOR_SOCKS_PORT}"
        assertTrue(config.contains("proxy = '$proxy'"))
        assertTrue(
            config.contains(
                "bootstrap_resolvers = ['${TunnelEndpoints.LOOPBACK}:${TunnelEndpoints.TOR_DNS_PORT}']",
            ),
        )
        assertTrue(config.contains("netprobe_address = '${TunnelEndpoints.LOOPBACK}:${TunnelEndpoints.TOR_DNS_PORT}'"))
        assertTrue(config.contains("ignore_system_dns = true"))
        assertTrue(config.contains("force_tcp = true"))
        assertTrue(config.contains("dnscrypt_ephemeral_keys = true"))
        assertTrue(config.contains("tls_disable_session_tickets = true"))
        assertTrue(config.contains("block_ipv6 = false"))
        assertTrue(config.contains("ipv6_servers = true"))
        assertTrue(config.contains("require_dnssec = true"))
        assertTrue(config.contains("[sources.'public-resolvers']"))
        assertTrue(config.contains("server_names = ['cloudflare']"))
    }

    @Test
    fun knownServerStampsAreDistinct() {
        assertTrue(DnsCryptPublicResolvers.knownServers.size > 100)
        assertTrue(DnsCryptConfigWriter.stampFor("cloudflare") != DnsCryptConfigWriter.stampFor("adguard-dns"))
        assertTrue(
            DnsCryptConfigWriter.stampFor("quad9-dnscrypt-ip4-nofilter-pri") !=
                DnsCryptConfigWriter.stampFor("adguard-dns"),
        )
        assertTrue(DnsCryptConfigWriter.stampFor("cloudflare").startsWith("sdns://"))
        assertEquals("adguard-dns", DnsCryptPublicResolvers.resolveName("adguard"))
        assertEquals("quad9-dnscrypt-ip4-nofilter-pri", DnsCryptPublicResolvers.resolveName("quad9"))
    }

    @Test
    fun autoModeOmitsServerNamesAndStaticStamp() {
        val config = DnsCryptConfigWriter.write(
            configDirectory = "/tmp",
            serverName = DnsCryptPublicResolvers.AUTO,
        )
        assertFalse(config.contains("server_names ="))
        assertFalse(config.contains("[static]"))
        assertTrue(config.contains("[sources.'public-resolvers']"))
    }
}
