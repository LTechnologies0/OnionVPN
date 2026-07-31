package ltechnologies.onionphone.onionvpn.core.tor.config

import java.io.File
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class TorBridgeConfigTest {
    @get:Rule
    val tmp = TemporaryFolder()

    @Test
    fun detectsTransports() {
        assertEquals("obfs4", TorBridgeConfig.transportOf("obfs4 1.2.3.4:443 FPR cert=x iat-mode=0"))
        assertEquals("snowflake", TorBridgeConfig.transportOf("Bridge snowflake 192.0.2.3:80 FPR"))
        assertEquals("webtunnel", TorBridgeConfig.transportOf("webtunnel 192.0.2.1:443 FPR url=https://x.example"))
        assertEquals("conjure", TorBridgeConfig.transportOf("conjure 192.0.2.1:443 FPR"))
        assertEquals("meek_lite", TorBridgeConfig.transportOf("meek_lite 192.0.2.20:80 url=https://x front=y"))
        assertEquals(null, TorBridgeConfig.transportOf("1.2.3.4:443 AABBCC"))
    }

    @Test
    fun lyrebirdEmitsFullTorBrowserCtp() {
        val libDir = tmp.newFolder("lib")
        File(libDir, TorBridgeConfig.LIB_LYREBIRD).writeText("fake")
        File(libDir, TorBridgeConfig.LIB_CONJURE).writeText("fake")
        val fragment = TorBridgeConfig.torrcFragment(
            bridgeText = "obfs4 192.95.36.142:443 CDF2 cert=qUV iat-mode=1",
            nativeLibraryDir = libDir,
        )
        assertTrue(fragment.contains("UseBridges 1"))
        assertTrue(fragment.contains("ClientTransportPlugin meek_lite,obfs2,obfs3,obfs4,scramblesuit,webtunnel exec "))
        assertTrue(fragment.contains("ClientTransportPlugin snowflake exec "))
        assertTrue(fragment.contains("ClientTransportPlugin conjure exec "))
        assertTrue(fragment.contains(TorBridgeConfig.CONJURE_REGISTER_URL))
        assertTrue(fragment.contains(TorBridgeConfig.LIB_LYREBIRD))
        assertTrue(fragment.contains("Bridge obfs4 192.95.36.142:443"))
    }

    @Test
    fun legacyFallbackWithoutLyrebird() {
        val libDir = tmp.newFolder("lib")
        File(libDir, TorBridgeConfig.LIB_OBFS4PROXY).writeText("fake")
        val lines = TorBridgeConfig.clientTransportPluginLines(
            bridgeText = "meek_lite 192.0.2.20:80 url=https://example front=x",
            nativeLibraryDir = libDir,
        )
        assertEquals(1, lines.size)
        assertTrue(lines[0].startsWith("ClientTransportPlugin meek_lite exec "))
        assertTrue(lines[0].contains(TorBridgeConfig.LIB_OBFS4PROXY))
    }

    @Test
    fun snowflakeViaLyrebird() {
        val libDir = tmp.newFolder("lib")
        File(libDir, TorBridgeConfig.LIB_LYREBIRD).writeText("fake")
        val lines = TorBridgeConfig.clientTransportPluginLines(
            bridgeText = "snowflake 192.0.2.3:80 FPR fingerprint=FPR",
            nativeLibraryDir = libDir,
        )
        assertTrue(lines.any { it.contains("snowflake exec ") && it.contains(TorBridgeConfig.LIB_LYREBIRD) })
    }

    @Test
    fun webtunnelRequiresLyrebirdOrObfs4proxy() {
        val libDir = tmp.newFolder("lib")
        File(libDir, TorBridgeConfig.LIB_LYREBIRD).writeText("fake")
        val fragment = TorBridgeConfig.torrcFragment(
            bridgeText = "webtunnel [2001:db8::1]:443 FPR url=https://wt.example/ path=/tor",
            nativeLibraryDir = libDir,
        )
        assertTrue(fragment.contains("Bridge webtunnel "))
        assertTrue(fragment.contains("webtunnel exec ") || fragment.contains("scramblesuit,webtunnel"))
    }

    @Test
    fun torConfigWriterIncludesLyrebirdCtp() {
        val libDir = tmp.newFolder("lib")
        File(libDir, TorBridgeConfig.LIB_LYREBIRD).writeText("fake")
        val torrc = TorConfigWriter.write(
            dataDirectory = tmp.newFolder("tor").absolutePath,
            preferences = TunnelPreferences(
                torBridges = "obfs4 1.2.3.4:443 FPR cert=x iat-mode=0",
            ),
            nativeLibraryDir = libDir.absolutePath,
        )
        assertTrue(torrc.contains("UseBridges 1"))
        assertTrue(torrc.contains("ClientTransportPlugin meek_lite,obfs2,obfs3,obfs4,scramblesuit,webtunnel exec "))
        assertFalse(torrc.contains("libobfs4proxy"))
    }
}
