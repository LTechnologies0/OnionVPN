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
            "android.dns.private",
            "android.vpn.route.default",
            "android.vpn.route.ipv6",
            // Hard only when inspector sets tripsKillSwitch (other app owns Always-on /
            // Private DNS hostname|active). Missing Lockdown / opportunistic are Soft.
            "android.vpn.always_on",
            "vpn.address.not.public",
            "tor.arti.status",
            "tor.config.content",
            "tor.config.missing",
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

    @Test
    fun validationTimeoutIsSoftEvenIfFlagged() {
        // Exit-IP / remote probes can exceed budget while Tor SOCKS still works —
        // must not blackhole working torrified traffic.
        val check = ValidationCheck(
            id = "validation.timeout",
            label = "Tunnel validation",
            status = ValidationStatus.Fail,
            detail = "timed out",
            tripsKillSwitch = true,
        )
        assertFalse(TunnelValidator.isHardKillSwitchFailure(check))
    }

    @Test
    fun privateDnsActiveIsHard() {
        val check = ValidationCheck(
            id = "android.dns.private",
            label = "Private DNS",
            status = ValidationStatus.Fail,
            detail = "DoT active",
            tripsKillSwitch = true,
        )
        assertTrue(TunnelValidator.isHardKillSwitchFailure(check))
    }

    @Test
    fun opportunisticPrivateDnsNotHardWhenSoft() {
        val check = ValidationCheck(
            id = "android.dns.private",
            label = "Private DNS",
            status = ValidationStatus.Fail,
            detail = "Private DNS mode=opportunistic (stock default)",
            tripsKillSwitch = false,
        )
        assertFalse(TunnelValidator.isHardKillSwitchFailure(check))
    }

    @Test
    fun alwaysOnWithoutLockdownIsHard() {
        val check = ValidationCheck(
            id = "android.vpn.always_on",
            label = "Android Always-on VPN lockdown",
            status = ValidationStatus.Fail,
            detail = "Always-on ON but Lockdown OFF",
            tripsKillSwitch = true,
        )
        assertTrue(TunnelValidator.isHardKillSwitchFailure(check))
    }

    @Test
    fun missingAlwaysOnStillSoftWhenNotTripping() {
        val check = ValidationCheck(
            id = "android.vpn.always_on",
            label = "Android Always-on VPN lockdown",
            status = ValidationStatus.Fail,
            detail = "Settings → enable Always-on + Lockdown",
            tripsKillSwitch = false,
        )
        assertFalse(TunnelValidator.isHardKillSwitchFailure(check))
    }

    @Test
    fun isTorFalseIsSoft() {
        val check = ValidationCheck(
            id = "tor.exit.istor",
            label = "IsTor",
            status = ValidationStatus.Fail,
            detail = "IsTor=false IP=1.2.3.4 — Soft warn",
            tripsKillSwitch = false,
        )
        assertFalse(TunnelValidator.isHardKillSwitchFailure(check))
    }

    @Test
    fun emptyVpnAddrsSoftNotHard() {
        val check = ValidationCheck(
            id = "vpn.address.not.public",
            label = "VPN addresses",
            status = ValidationStatus.Fail,
            detail = "No VPN link addresses found (CM race)",
            tripsKillSwitch = false,
        )
        assertFalse(TunnelValidator.isHardKillSwitchFailure(check))
    }

    @Test
    fun ispIpOnExitPathIsHard() {
        val check = ValidationCheck(
            id = "tor.exit.ip",
            label = "Egress",
            status = ValidationStatus.Fail,
            detail = "Egress 1.2.3.4 equals device non-VPN address — ISP IP leak",
            tripsKillSwitch = true,
        )
        assertTrue(TunnelValidator.isHardKillSwitchFailure(check))
    }
}
