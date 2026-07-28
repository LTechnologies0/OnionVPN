package ltechnologies.onionphone.onionvpn.core.dnscrypt.config

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
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
        assertTrue(config.contains("require_dnssec = true"))
    }

    @Test
    fun knownServerStampsAreDistinct() {
        val stamps = DnsCryptConfigWriter.knownServers.values.toSet()
        assertTrue(stamps.size == DnsCryptConfigWriter.knownServers.size)
        assertTrue(DnsCryptConfigWriter.stampFor("cloudflare") != DnsCryptConfigWriter.stampFor("adguard"))
        assertTrue(DnsCryptConfigWriter.stampFor("quad9") != DnsCryptConfigWriter.stampFor("adguard"))
        assertTrue(DnsCryptConfigWriter.stampFor("cloudflare").startsWith("sdns://"))
    }
}
