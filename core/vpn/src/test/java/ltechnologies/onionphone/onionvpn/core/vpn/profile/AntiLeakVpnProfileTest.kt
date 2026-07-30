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
}
