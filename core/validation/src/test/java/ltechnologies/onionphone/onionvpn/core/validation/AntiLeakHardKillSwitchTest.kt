package ltechnologies.onionphone.onionvpn.core.validation

import ltechnologies.onionphone.onionvpn.core.model.ValidationCheck
import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import ltechnologies.onionphone.onionvpn.core.dnscrypt.config.DnsCryptConfigWriter
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.validation.path.DnsCryptPathValidator
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

@RunWith(Parameterized::class)
class AntiLeakHardKillSwitchIdsTest(private val id: String) {
    @Test
    fun dnscryptWiringFailuresAreHardKillSwitch() {
        val check = ValidationCheck(
            id = id,
            label = id,
            status = ValidationStatus.Fail,
            detail = "test",
            tripsKillSwitch = true,
        )
        assertTrue(
            "Expected hard kill-switch for $id",
            TunnelValidator.isHardKillSwitchFailure(check),
        )
    }

    companion object {
        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun ids(): List<Array<String>> = listOf(
            "dnscrypt.tor.wiring",
            "dnscrypt.tor.wiring.missing",
            "dnscrypt.config.runtime",
            "dnscrypt.config.missing",
            "dns.mode.mapdns",
            "uid.forwarder.wiring",
            "tor.socks",
            "vpn.not.established",
        ).map { arrayOf(it) }
    }
}

class AntiLeakDnsCryptConfigValidatorTest {
    @Test
    fun validGeneratedConfigPasses() {
        val config = DnsCryptConfigWriter.write(
            configDirectory = "/tmp",
            listenPort = TunnelEndpoints.DNSCRYPT_LISTEN_PORT,
            torSocksPort = 19051,
            torDnsPort = 19053,
        )
        val check = DnsCryptPathValidator.validateConfigContent(
            config = config,
            source = "test",
            listenPort = TunnelEndpoints.DNSCRYPT_LISTEN_PORT,
            torSocksPort = 19051,
            torDnsPort = 19053,
        )
        assertTrue(check.detail, check.status == ValidationStatus.Pass)
        assertFalse(check.tripsKillSwitch)
    }

    @Test
    fun missingForceTcpFailsAndTripsKillSwitch() {
        val bad = DnsCryptConfigWriter.write(configDirectory = "/tmp")
            .replace("force_tcp = true", "force_tcp = false")
        val check = DnsCryptPathValidator.validateConfigContent(bad, source = "bad")
        assertTrue(check.status == ValidationStatus.Fail)
        assertTrue(check.tripsKillSwitch)
        assertTrue(check.detail.contains("force_tcp=false") || check.detail.contains("force_tcp="))
    }

    @Test
    fun softListenerFlakeNotHard() {
        val check = ValidationCheck(
            id = "dnscrypt.listener",
            label = "listener",
            status = ValidationStatus.Fail,
            detail = "timeout",
            tripsKillSwitch = false,
        )
        assertFalse(TunnelValidator.isHardKillSwitchFailure(check))
    }
}
