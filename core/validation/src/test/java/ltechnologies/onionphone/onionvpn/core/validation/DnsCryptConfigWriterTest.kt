package ltechnologies.onionphone.onionvpn.core.validation

import ltechnologies.onionphone.onionvpn.core.dnscrypt.DnsCryptConfigWriter
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsCryptConfigWriterTest {
    @Test
    fun forcesUpstreamThroughTorAndBootstrapThroughDnsPort() {
        val config = DnsCryptConfigWriter.write(configDirectory = "/tmp")

        assertTrue(config.contains("proxy = 'socks5://${TunnelEndpoints.LOOPBACK}:${TunnelEndpoints.TOR_SOCKS_PORT}'"))
        assertTrue(
            config.contains(
                "bootstrap_resolvers = ['${TunnelEndpoints.LOOPBACK}:${TunnelEndpoints.TOR_DNS_PORT}']",
            ),
        )
        assertTrue(config.contains("netprobe_address = '${TunnelEndpoints.LOOPBACK}:${TunnelEndpoints.TOR_DNS_PORT}'"))
        assertTrue(config.contains("ignore_system_dns = true"))
        assertTrue(config.contains("force_tcp = true"))
    }
}
