package ltechnologies.onionphone.onionvpn.core.tor

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TorConfigWriterTest {
    @Test
    fun streamIsolation_maxFlags_threeSocksPorts_noKeepAliveOnApps() {
        val torrc = TorConfigWriter.write(
            dataDirectory = "/tmp/tor",
            socksPort = 1111,
            dnsCryptSocksPort = 2222,
            probeSocksPort = 3333,
            dnsPort = 4444,
            preferences = TunnelPreferences(torMaxCircuitDirtinessSec = 180),
        )

        assertTrue(torrc.contains("SOCKSPort ${TunnelEndpoints.LOOPBACK}:1111"))
        assertTrue(torrc.contains("SOCKSPort ${TunnelEndpoints.LOOPBACK}:2222"))
        assertTrue(torrc.contains("SOCKSPort ${TunnelEndpoints.LOOPBACK}:3333"))
        assertTrue(torrc.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_APPS}"))
        assertTrue(torrc.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_DNSCRYPT}"))
        assertTrue(torrc.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_PROBE}"))
        assertTrue(torrc.contains("IsolateClientAddr"))
        assertTrue(torrc.contains("IsolateClientProtocol"))
        assertTrue(torrc.contains("IsolateDestAddr"))
        assertTrue(torrc.contains("IsolateDestPort"))
        assertTrue(torrc.contains("IsolateSOCKSAuth"))
        assertTrue(torrc.contains("MaxClientCircuitsPending 128"))
        assertTrue(torrc.contains("MaxCircuitDirtiness 180"))

        val appLine = torrc.lineSequence().first {
            it.startsWith("SOCKSPort ") &&
                it.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_APPS}")
        }
        assertFalse(
            "KeepAliveIsolateSOCKSAuth on app SocksPort would pin shared hev auth circuits",
            appLine.contains("KeepAliveIsolateSOCKSAuth"),
        )
        val dnsCryptLine = torrc.lineSequence().first {
            it.startsWith("SOCKSPort ") &&
                it.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_DNSCRYPT}")
        }
        assertTrue(dnsCryptLine.contains("KeepAliveIsolateSOCKSAuth"))
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
