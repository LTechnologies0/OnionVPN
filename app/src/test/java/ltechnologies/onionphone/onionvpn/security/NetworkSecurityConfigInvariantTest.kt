package ltechnologies.onionphone.onionvpn.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * App-owned HTTPS must not trust user-installed CAs (classic local MitM via
 * mitmproxy / sslstrip-class proxies that install a user CA).
 */
class NetworkSecurityConfigInvariantTest {
    @Test
    fun trustAnchorsAreSystemOnly() {
        val xml = resolveNsc().readText()
        assertTrue(
            "network_security_config must trust system CAs",
            xml.contains("""src="system"""") || xml.contains("src='system'"),
        )
        assertFalse(
            "network_security_config must not trust user CAs",
            xml.contains("""src="user"""") || xml.contains("src='user'"),
        )
        assertTrue(
            "cleartext must be off in base-config",
            xml.contains("cleartextTrafficPermitted=\"false\""),
        )
    }

    private fun resolveNsc(): File {
        val candidates = listOf(
            File("src/main/res/xml/network_security_config.xml"),
            File("app/src/main/res/xml/network_security_config.xml"),
        )
        return candidates.firstOrNull { it.isFile }
            ?: error("network_security_config.xml not found from cwd=${File(".").absolutePath}")
    }
}
