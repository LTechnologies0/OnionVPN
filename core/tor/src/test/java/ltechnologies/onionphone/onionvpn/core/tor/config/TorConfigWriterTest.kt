package ltechnologies.onionphone.onionvpn.core.tor.config

import ltechnologies.onionphone.onionvpn.core.model.TorStreamIsolationMode
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TorConfigWriterTest {
    @Test
    fun streamIsolation_balancedApps_noDestIsolation_noKeepAliveOnApps() {
        val torrc = TorConfigWriter.write(
            dataDirectory = "/tmp/tor",
            socksPort = 1111,
            dnsCryptSocksPort = 2222,
            probeSocksPort = 3333,
            dnsPort = 4444,
            preferences = TunnelPreferences(
                torMaxCircuitDirtinessSec = 600,
                torStreamIsolation = TorStreamIsolationMode.BALANCED,
            ),
        )

        assertTrue(torrc.contains("SOCKSPort ${TunnelEndpoints.LOOPBACK}:1111"))
        assertTrue(torrc.contains("SOCKSPort ${TunnelEndpoints.LOOPBACK}:2222"))
        assertTrue(torrc.contains("SOCKSPort ${TunnelEndpoints.LOOPBACK}:3333"))
        assertTrue(torrc.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_APPS}"))
        assertTrue(torrc.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_DNSCRYPT}"))
        assertTrue(torrc.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_PROBE}"))
        assertTrue(torrc.contains("IsolateSOCKSAuth"))
        assertTrue(torrc.contains("MaxClientCircuitsPending 32"))
        assertTrue(torrc.contains("MaxCircuitDirtiness 600"))
        assertTrue(torrc.contains("CircuitStreamTimeout 30"))
        assertTrue(torrc.contains("ReducedConnectionPadding 1"))
        assertTrue(torrc.contains("ReducedCircuitPadding 1"))

        val appLine = torrc.lineSequence().first {
            it.startsWith("SOCKSPort ") &&
                it.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_APPS}")
        }
        assertFalse(
            "Balanced apps SocksPort must not pin destinations (Orbot-like)",
            appLine.contains("IsolateDestAddr") || appLine.contains("IsolateDestPort"),
        )
        assertFalse(
            "KeepAliveIsolateSOCKSAuth on app SocksPort would pin shared hev auth circuits",
            appLine.contains("KeepAliveIsolateSOCKSAuth"),
        )
        val dnsCryptLine = torrc.lineSequence().first {
            it.startsWith("SOCKSPort ") &&
                it.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_DNSCRYPT}")
        }
        assertTrue(dnsCryptLine.contains("KeepAliveIsolateSOCKSAuth"))
        assertTrue(dnsCryptLine.contains("IsolateDestAddr"))
    }

    @Test
    fun streamIsolation_strictApps_hasDestIsolation() {
        val torrc = TorConfigWriter.write(
            dataDirectory = "/tmp/tor",
            preferences = TunnelPreferences(
                torStreamIsolation = TorStreamIsolationMode.STRICT,
            ),
        )
        val appLine = torrc.lineSequence().first {
            it.startsWith("SOCKSPort ") &&
                it.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_APPS}")
        }
        assertTrue(appLine.contains("IsolateDestAddr"))
        assertTrue(appLine.contains("IsolateDestPort"))
        assertFalse(appLine.contains("KeepAliveIsolateSOCKSAuth"))
    }

    @Test
    fun mitmHardening_rejectInternal_safeLogging_refuseUnknownExits() {
        val torrc = TorConfigWriter.write(dataDirectory = "/tmp/tor")
        assertTrue(torrc.contains("ClientRejectInternalAddresses 1"))
        assertTrue(torrc.contains("SafeLogging 1"))
        assertTrue(torrc.contains("RefuseUnknownExits 1"))
        assertTrue(torrc.contains("AllowNonRFC953Hostnames 0"))
        assertTrue(torrc.contains("ClientPreferIPv6ORPort 0"))
        assertTrue(torrc.contains("RejectPlaintextPorts 23,109"))
        assertFalse(torrc.contains("GeoIPExcludeUnknown"))
        assertTrue(torrc.contains("CookieAuthentication 1"))
        assertTrue(torrc.contains("ControlSocket "))
        assertTrue(torrc.contains(TorConfigWriter.CONTROL_SOCKET_NAME))
        assertTrue(torrc.contains(TorConfigWriter.COOKIE_FILE_NAME))
    }
}
