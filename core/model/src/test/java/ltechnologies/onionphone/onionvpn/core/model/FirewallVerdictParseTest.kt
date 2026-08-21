package ltechnologies.onionphone.onionvpn.core.model

import org.junit.Assert.assertEquals
import org.junit.Test

class FirewallVerdictParseTest {
    @Test
    fun legacyAllowMapsToAllowTor() {
        assertEquals(FirewallVerdict.ALLOW_TOR, FirewallVerdict.parse("ALLOW"))
        assertEquals(FirewallVerdict.ALLOW_TOR, FirewallVerdict.parse("ALLOW_TOR"))
        assertEquals(FirewallVerdict.ALLOW_OVPN, FirewallVerdict.parse("ALLOW_OVPN"))
        assertEquals(FirewallVerdict.DENY, FirewallVerdict.parse("DENY"))
    }

    @Test
    fun forwardsFlags() {
        assertEquals(true, FirewallVerdict.ALLOW_TOR.forwards)
        assertEquals(true, FirewallVerdict.ALLOW_OVPN.forwards)
        assertEquals(false, FirewallVerdict.DENY.forwards)
    }
}
