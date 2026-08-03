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
        assertTrue(config.contains("block_ipv6 = true"))
        assertTrue(config.contains("ipv6_servers = false"))
        assertTrue(config.contains("require_dnssec = true"))
        assertTrue(config.contains("[sources.'public-resolvers']"))
        // DoH-only defaults get classic DNSCrypt peers prepended for Tor SOCKS reliability.
        assertTrue(config.contains("server_names = ['adguard-dns', 'cs-de', 'cs-nl', 'cloudflare']"))
        assertTrue(config.contains("[static.'adguard-dns']"))
        assertTrue(config.contains("[static.'cloudflare']"))
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

    @Test
    fun multiServerNames_emitsStaticBlocks() {
        val config = DnsCryptConfigWriter.write(
            configDirectory = "/tmp",
            serverName = "cloudflare,adguard-dns",
        )
        assertTrue(config.contains("server_names = ['cloudflare', 'adguard-dns']"))
        assertTrue(config.contains("[static.'cloudflare']"))
        assertTrue(config.contains("[static.'adguard-dns']"))
    }

    @Test
    fun onionmasqSidecarSocksPort_appearsInProxyLine() {
        val sidecar = 19050
        val config = DnsCryptConfigWriter.write(
            configDirectory = "/tmp",
            torSocksPort = sidecar,
            torDnsPort = 19053,
        )
        val proxy =
            "socks5://${TunnelEndpoints.SOCKS_DNSCRYPT_USER}:${TunnelEndpoints.SOCKS_DNSCRYPT_PASS}" +
                "@${TunnelEndpoints.LOOPBACK}:$sidecar"
        assertTrue(config.contains("proxy = '$proxy'"))
        assertTrue(config.contains("bootstrap_resolvers = ['${TunnelEndpoints.LOOPBACK}:19053']"))
        assertTrue(config.contains("force_tcp = true"))
        assertTrue(config.contains("ignore_system_dns = true"))
    }
}
