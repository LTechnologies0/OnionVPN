package ltechnologies.onionphone.onionvpn.core.tor.config

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TorConfigWriterTest {
    @Test
    fun streamIsolation_appsWithoutDestPort_keepAlive_mobileGuards() {
        val torrc = TorConfigWriter.write(
            dataDirectory = "/tmp/tor",
            socksPort = 1111,
            dnsCryptSocksPort = 2222,
            probeSocksPort = 3333,
            httpTunnelPort = 5555,
            dnsPort = 4444,
            preferences = TunnelPreferences(torMaxCircuitDirtinessSec = 600),
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
        assertTrue(torrc.contains("IsolateSOCKSAuth"))
        assertTrue(torrc.contains("MaxClientCircuitsPending 32"))
        assertTrue(torrc.contains("MaxCircuitDirtiness 600"))
        assertTrue(torrc.contains("NumEntryGuards 2"))
        assertTrue(torrc.contains("NumPrimaryGuards 2"))
        assertTrue(torrc.contains("DormantClientTimeout 30 minutes"))

        val appLine = torrc.lineSequence().first {
            it.startsWith("SOCKSPort ") &&
                it.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_APPS}")
        }
        assertTrue(
            "KeepAliveIsolateSOCKSAuth required for per-UID strong isolation tokens",
            appLine.contains("KeepAliveIsolateSOCKSAuth"),
        )
        assertFalse(
            "Apps SocksPort must omit IsolateDestPort (circuit storm / Whonix #3455)",
            appLine.contains("IsolateDestPort"),
        )
        val dnsCryptLine = torrc.lineSequence().first {
            it.startsWith("SOCKSPort ") &&
                it.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_DNSCRYPT}")
        }
        assertTrue(dnsCryptLine.contains("KeepAliveIsolateSOCKSAuth"))
        assertTrue(dnsCryptLine.contains("IsolateDestPort"))
        assertTrue(torrc.contains("SafeSocks 0"))
        assertTrue(torrc.contains("TestSocks 0"))
        assertTrue(torrc.contains("HTTPTunnelPort 0"))
        assertTrue(torrc.contains("AutomapHostsOnResolve 1"))
        assertTrue(torrc.contains("AutomapHostsSuffixes .onion,.exit"))
        assertTrue(torrc.contains("VirtualAddrNetwork 10.192.0.0/10"))
        assertTrue(torrc.contains("DNSPort ${TunnelEndpoints.LOOPBACK}:4444"))
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
