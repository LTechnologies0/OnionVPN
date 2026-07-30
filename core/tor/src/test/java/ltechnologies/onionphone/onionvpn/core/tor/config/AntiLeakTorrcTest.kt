package ltechnologies.onionphone.onionvpn.core.tor.config

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

/**
 * Parameterized anti-leak assertions for generated torrc (AL catalog torrc bucket).
 */
@RunWith(Parameterized::class)
class AntiLeakTorrcTest(private val requiredSubstring: String) {
    @Test
    fun torrcContainsRequiredPolicy() {
        val torrc = TorConfigWriter.write(
            dataDirectory = "/data/local/tmp/onionvpn-tor",
            socksPort = 19_050,
            dnsCryptSocksPort = 19_051,
            probeSocksPort = 19_052,
            httpTunnelPort = 19_053,
            dnsPort = 19_053,
            preferences = TunnelPreferences(),
        )
        assertTrue(
            "Missing torrc policy: $requiredSubstring\n---\n$torrc",
            torrc.contains(requiredSubstring),
        )
    }

    companion object {
        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun policies(): List<Array<String>> = listOf(
            "ClientOnly 1",
            "SocksPolicy accept 127.0.0.1",
            "SocksPolicy reject *",
            "AutomapHostsOnResolve 1",
            "AutomapHostsSuffixes .onion,.exit",
            "TransPort 0",
            "HTTPTunnelPort 0",
            "ControlPort 0",
            "CookieAuthentication 1",
            "ClientRejectInternalAddresses 1",
            "RefuseUnknownExits 1",
            "UseEntryGuards 1",
            "KeepAliveIsolateSOCKSAuth",
            "IsolateSOCKSAuth",
            "IsolateClientAddr",
            "IsolateClientProtocol",
            "IsolateDestAddr",
            "VirtualAddrNetwork 10.192.0.0/10",
            "SafeLogging 1",
            "SessionGroup=${TunnelEndpoints.SESSION_GROUP_APPS}",
            "SessionGroup=${TunnelEndpoints.SESSION_GROUP_DNSCRYPT}",
            "SessionGroup=${TunnelEndpoints.SESSION_GROUP_PROBE}",
            "SessionGroup=${TunnelEndpoints.SESSION_GROUP_DNS}",
            "MaxClientCircuitsPending 48",
            "VanguardsLiteEnabled 1",
            "WarnPlaintextPorts 23,109,110,143",
            "RejectPlaintextPorts 23,109",
            "FetchUselessDescriptors 0",
            "DownloadExtraInfo 0",
            "ClientPreferIPv6ORPort 0",
            "EnforceDistinctSubnets 1",
            "NumEntryGuards 2",
            "NumPrimaryGuards 2",
            "NumDirectoryGuards 3",
            "CircuitPadding 1",
            "ConnectionPadding auto",
        ).map { arrayOf(it) }
    }
}

class AntiLeakTorrcIsolationTest {
    @Test
    fun appsSocksPortOmitsIsolateDestPort() {
        val torrc = TorConfigWriter.write(dataDirectory = "/tmp/t")
        val apps = torrc.lineSequence().first {
            it.startsWith("SOCKSPort ") && it.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_APPS}")
        }
        assertFalse(apps.contains("IsolateDestPort"))
        assertTrue(apps.contains("KeepAliveIsolateSOCKSAuth"))
    }

    @Test
    fun dnsCryptSocksPortIncludesIsolateDestPort() {
        val torrc = TorConfigWriter.write(dataDirectory = "/tmp/t")
        val line = torrc.lineSequence().first {
            it.startsWith("SOCKSPort ") &&
                it.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_DNSCRYPT}")
        }
        assertTrue(line.contains("IsolateDestPort"))
        assertTrue(line.contains("KeepAliveIsolateSOCKSAuth"))
    }
}
