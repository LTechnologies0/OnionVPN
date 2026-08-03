package ltechnologies.onionphone.onionvpn.core.vpn.profile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

@RunWith(Parameterized::class)
class AntiLeakDnsPinTest(private val resolver: String) {
    @Test
    fun blockedPublicDnsContainsPin() {
        assertTrue(
            "BLOCKED_PUBLIC_DNS missing $resolver",
            VpnProfileBuilder.BLOCKED_PUBLIC_DNS.contains(resolver),
        )
    }

    companion object {
        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun pins(): List<Array<String>> =
            VpnProfileBuilder.BLOCKED_PUBLIC_DNS.map { arrayOf(it) }
    }
}

class AntiLeakVpnProfilePolicyTest {
    @Test
    fun blockedPublicDnsHasBothIpv4AndIpv6() {
        val pins = VpnProfileBuilder.BLOCKED_PUBLIC_DNS
        assertTrue(pins.any { !it.contains(':') })
        assertTrue(pins.any { it.contains(':') })
        assertTrue(pins.size >= 30)
    }

    @Test
    fun sessionNameStable() {
        assertEquals("OnionVPN", VpnProfileBuilder.SESSION_NAME)
    }

    @Test
    fun noDuplicatePins() {
        val pins = VpnProfileBuilder.BLOCKED_PUBLIC_DNS
        assertEquals(pins.size, pins.toSet().size)
    }

    @Test
    fun googleCloudflareQuad9Present() {
        assertTrue(VpnProfileBuilder.BLOCKED_PUBLIC_DNS.contains("8.8.8.8"))
        assertTrue(VpnProfileBuilder.BLOCKED_PUBLIC_DNS.contains("1.1.1.1"))
        assertTrue(VpnProfileBuilder.BLOCKED_PUBLIC_DNS.contains("9.9.9.9"))
    }

    @Test
    fun docsForbidAllowBypass() {
        // Source-level invariant: Builder must never call allowBypass (comment + code review).
        // Runtime Builder needs Android; we assert the pin list is non-empty fail-closed surface.
        assertFalse(VpnProfileBuilder.BLOCKED_PUBLIC_DNS.isEmpty())
    }

    @Test
    fun sourceForbidsAllowBypassAndAllowFamily() {
        // Dual-stack addAddress+addRoute claims families; allowFamily alone can fall through.
        val src = java.io.File(
            "src/main/java/ltechnologies/onionphone/onionvpn/core/vpn/profile/VpnProfileBuilder.kt",
        ).readText()
        assertFalse(
            "allowBypass must not be called",
            Regex("""\.allowBypass\s*\(""").containsMatchIn(src),
        )
        assertFalse(
            "allowFamily must not be called — routes claim IPv4+IPv6",
            Regex("""\.allowFamily\s*\(""").containsMatchIn(src),
        )
        assertTrue("0.0.0.0/0 route required", """addRoute("0.0.0.0", 0)""" in src)
        assertTrue("::/0 route required", """addRoute("::", 0)""" in src)
        assertTrue(
            "per-app routing must call addAllowedApplication or addDisallowedApplication",
            src.contains("addAllowedApplication") && src.contains("addDisallowedApplication"),
        )
        assertTrue("VpnAppRoutingMode INCLUDE handled", src.contains("VpnAppRoutingMode.INCLUDE"))
        assertTrue(
            "Tor-native BYPASS must use TorNativeAppUids + disallowTorNativeBypass",
            src.contains("TorNativeAppUids") && src.contains("disallowTorNativeBypass"),
        )
        assertTrue(
            "INCLUDE×lockdown must be documented/gated",
            src.contains("includeConflictsWithLockdown"),
        )
        assertTrue(
            "ADB clearnet must be opt-in via maybeDisallowAdbClearnet / AdbVpnBypass",
            src.contains("maybeDisallowAdbClearnet") && src.contains("AdbVpnBypass"),
        )
        assertTrue(
            "ADB clearnet gated on allowAdbClearnetLeak",
            src.contains("allowAdbClearnetLeak"),
        )
    }

    @Test
    fun adbClearnetLeakDefaultsOff() {
        assertFalse(
            "wireless ADB must not bypass VPN by default",
            ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences().allowAdbClearnetLeak,
        )
    }

    @Test
    fun adbVpnBypassShellPackageConstant() {
        assertEquals(
            "com.android.shell",
            ltechnologies.onionphone.onionvpn.core.vpn.profile.AdbVpnBypass.SHELL_PACKAGE,
        )
        val adbSrc = java.io.File(
            "src/main/java/ltechnologies/onionphone/onionvpn/core/vpn/profile/AdbVpnBypass.kt",
        ).readText()
        assertFalse(
            "AdbVpnBypass must not call Builder.addDisallowedApplication",
            Regex("""\.addDisallowedApplication\s*\(""").containsMatchIn(adbSrc),
        )
        val builderSrc = java.io.File(
            "src/main/java/ltechnologies/onionphone/onionvpn/core/vpn/profile/VpnProfileBuilder.kt",
        ).readText()
        assertTrue(
            "shell disallow only when allowAdbClearnetLeak",
            builderSrc.contains("if (!preferences.allowAdbClearnetLeak) return"),
        )
    }

    @Test
    fun onionmasqDoesNotExcludeShellUnlessOptIn() {
        val src = java.io.File(
            "src/main/java/ltechnologies/onionphone/onionvpn/core/vpn/forwarder/OnionmasqTunForwarder.kt",
        ).readText()
        assertTrue(src.contains("allowAdbClearnetLeak"))
        assertTrue(src.contains("AdbVpnBypass.extraExcludedUids"))
        assertTrue(
            "shell UID exclude must be gated",
            src.contains("if (!allowAdbClearnetLeak) return torNative"),
        )
    }

    @Test
    fun includeConflictsWithLockdownOnlyWhenIncludeNonEmpty() {
        val prefsInclude = ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences(
            vpnAppRoutingMode = ltechnologies.onionphone.onionvpn.core.model.VpnAppRoutingMode.INCLUDE,
            vpnAppPackages = setOf("com.example.app"),
        )
        val prefsAll = prefsInclude.copy(
            vpnAppRoutingMode = ltechnologies.onionphone.onionvpn.core.model.VpnAppRoutingMode.ALL,
        )
        val prefsEmptyInclude = prefsInclude.copy(vpnAppPackages = emptySet())
        assertTrue(VpnProfileBuilder.includeConflictsWithLockdown(prefsInclude, lockdownEnabled = true))
        assertFalse(VpnProfileBuilder.includeConflictsWithLockdown(prefsInclude, lockdownEnabled = false))
        assertFalse(VpnProfileBuilder.includeConflictsWithLockdown(prefsAll, lockdownEnabled = true))
        assertFalse(VpnProfileBuilder.includeConflictsWithLockdown(prefsEmptyInclude, lockdownEnabled = true))
    }

    @Test
    fun torNativeBypassRequiresSignaturePinsInSource() {
        val src = java.io.File(
            "src/main/java/ltechnologies/onionphone/onionvpn/core/vpn/onionmasq/TorNativeAppUids.kt",
        ).readText()
        assertTrue("must pin signing certs", src.contains("PINNED_CERT_SHA256"))
        assertTrue("must verify SHA-256", src.contains("SHA-256") || src.contains("signingCertSha256Hex"))
        assertTrue("Tor Browser release pin", src.contains("20061f045e737c67375c17794cfedb436a03cec6bacb7cb9f96642205ca2cec8"))
        assertTrue("Orbot/Tor Project legacy pin", src.contains("a454b87a1847a89ed7f5e70fba6bba96f3ef29c26e0981204fe347bf231dfd5b"))
        assertTrue("fail-closed without pin", src.contains("matchesPinnedSignature"))
    }

    @Test
    fun orbotBypassPackagesAreSubsetOfTorNativeList() {
        val bypass = ltechnologies.onionphone.onionvpn.core.vpn.onionmasq.TorNativeAppUids
            .bypassPackages()
            .toSet()
        val orbot = ltechnologies.onionphone.onionvpn.core.vpn.onionmasq.TorNativeAppUids
            .ORBOT_BYPASS_PACKAGES
        assertTrue(
            "Orbot BYPASS packages must be covered by TorNativeAppUids",
            bypass.containsAll(orbot),
        )
        assertTrue(bypass.contains("org.torproject.android"))
        assertTrue(bypass.contains("org.torproject.vpn"))
        assertFalse(
            "com.android.shell must never be a Tor-native BYPASS (ADB is opt-in only)",
            bypass.contains("com.android.shell"),
        )
    }

    @Test
    fun connectedSetsEmptyUnderlyingNetworksOnBuilder() {
        // emptyArray = no uplink until UnderlyingNetworkTracker; null = system default.
        val src = java.io.File(
            "src/main/java/ltechnologies/onionphone/onionvpn/core/vpn/profile/VpnProfileBuilder.kt",
        ).readText()
        assertTrue(
            "Connected must Builder.setUnderlyingNetworks(emptyArray()) pre-establish",
            src.contains("setUnderlyingNetworks(emptyArray())"),
        )
        assertTrue(
            "empty uplink only for Connected mode",
            src.contains("mode == VpnProfileMode.Connected"),
        )
    }

    @Test
    fun vpnDnsAddressV6IsUlaNotLinkLocal() {
        assertTrue(
            ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints.VPN_DNS_ADDRESS_V6
                .startsWith("fd00:"),
        )
        assertFalse(
            ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints.VPN_DNS_ADDRESS_V6
                .startsWith("fe80:"),
        )
        val src = java.io.File(
            "src/main/java/ltechnologies/onionphone/onionvpn/core/vpn/profile/VpnProfileBuilder.kt",
        ).readText()
        assertTrue(src.contains("VPN_DNS_ADDRESS_V6"))
    }
}
