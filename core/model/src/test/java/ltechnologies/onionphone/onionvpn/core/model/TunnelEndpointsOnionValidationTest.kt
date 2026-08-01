package ltechnologies.onionphone.onionvpn.core.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Onion / exit address-spec: published v3 onions Pass; short fakes Fail.
 */
class TunnelEndpointsOnionValidationTest {
    @Test
    fun validOnionV3_passes() {
        assertTrue(TunnelEndpoints.isValidOnionHostname(TunnelEndpoints.WELL_KNOWN_ONION_DDG))
        assertTrue(TunnelEndpoints.isValidOnionHostname(TunnelEndpoints.WELL_KNOWN_ONION_TORPROJECT))
        assertTrue(
            TunnelEndpoints.isValidOnionHostname("www.${TunnelEndpoints.WELL_KNOWN_ONION_DDG}"),
        )
        assertTrue(TunnelEndpoints.isValidOnionHostname("${TunnelEndpoints.WELL_KNOWN_ONION_DDG}."))
        assertTrue(TunnelEndpoints.isOnionLikeHostname(TunnelEndpoints.WELL_KNOWN_ONION_DDG))
    }

    @Test
    fun invalidOnionFakes_fail() {
        assertFalse(TunnelEndpoints.isValidOnionHostname("adb.onion"))
        assertFalse(TunnelEndpoints.isValidOnionHostname("abc.onion"))
        assertFalse(TunnelEndpoints.isValidOnionHostname("example.onion"))
        assertFalse(TunnelEndpoints.isValidOnionHostname("not-an-onion.onion"))
        assertFalse(TunnelEndpoints.isValidOnionHostname("example.com"))
        assertFalse(TunnelEndpoints.isValidOnionHostname(""))
        // '0' / '1' / '8' / '9' are not onion base32
        assertFalse(
            TunnelEndpoints.isValidOnionHostname(
                "00000000000000000000000000000000000000000000000000000000.onion",
            ),
        )
        assertFalse(
            TunnelEndpoints.isValidOnionHostname(
                "${TunnelEndpoints.WELL_KNOWN_ONION_DDG}.com",
            ),
        )
    }

    @Test
    fun onionLike_stillRoutesMalformedToTorNotDnsCrypt() {
        // Automap candidate: must stay true so TunDnsMux never DNSCrypt-resolves fakes.
        assertTrue(TunnelEndpoints.isOnionLikeHostname("adb.onion"))
        assertTrue(TunnelEndpoints.isOnionLikeHostname("abc.onion"))
        assertFalse(TunnelEndpoints.isOnionLikeHostname("example.com"))
        assertFalse(TunnelEndpoints.isOnionLikeHostname("onion.com"))
    }

    @Test
    fun validExit_passes() {
        assertTrue(
            TunnelEndpoints.isValidExitHostname(
                "example.com.1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b.exit",
            ),
        )
        assertTrue(TunnelEndpoints.isValidExitHostname("mynickname.exit"))
        assertTrue(
            TunnelEndpoints.isValidExitHostname(
                "192.0.2.1.1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b.exit",
            ),
        )
    }

    @Test
    fun invalidExit_fails() {
        assertFalse(TunnelEndpoints.isValidExitHostname("bad..exit"))
        assertFalse(TunnelEndpoints.isValidExitHostname(".exit"))
        assertFalse(TunnelEndpoints.isValidExitHostname("example.com"))
        assertFalse(TunnelEndpoints.isValidExitHostname("too_long_nickname_here.exit"))
        assertFalse(TunnelEndpoints.isValidExitHostname("hop-with-dash.exit"))
    }

    @Test
    fun automapVirtualPool_documentationRanges() {
        assertTrue(TunnelEndpoints.isAutomapVirtualIpv4("10.192.0.1"))
        assertTrue(TunnelEndpoints.isAutomapVirtualIpv4("10.255.255.255"))
        assertFalse(TunnelEndpoints.isAutomapVirtualIpv4("10.8.0.2"))
        assertFalse(TunnelEndpoints.isAutomapVirtualIpv4("192.0.2.1"))
        assertFalse(TunnelEndpoints.isAutomapVirtualIpv4("not-an-ip"))
        // TUN ULA must not be Automap; dedicated Automap /48 must.
        assertFalse(TunnelEndpoints.isAutomapVirtualIpv6(TunnelEndpoints.VPN_CLIENT_ADDRESS_V6))
        assertFalse(TunnelEndpoints.isAutomapVirtualIpv6("fd00:8:8:8::1"))
        assertTrue(TunnelEndpoints.isAutomapVirtualIpv6("fd12:4e4b:6f6e::1"))
        assertFalse(TunnelEndpoints.isAutomapVirtualIpv6("fc00::1"))
    }
}
