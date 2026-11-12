package ltechnologies.onionphone.onionvpn.core.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FirewallRuleLanTest {
    @Test
    fun poisonLanAllow_emptyOrPublicDest() {
        assertTrue(
            rule(verdict = FirewallVerdict.ALLOW_LAN, destHost = "").isPoisonLanAllow(),
        )
        assertTrue(
            rule(verdict = FirewallVerdict.ALLOW_LAN, destHost = "8.8.8.8").isPoisonLanAllow(),
        )
        assertFalse(
            rule(verdict = FirewallVerdict.ALLOW_LAN, destHost = "192.168.0.186").isPoisonLanAllow(),
        )
        assertFalse(
            rule(verdict = FirewallVerdict.DENY, destHost = "").isPoisonLanAllow(),
        )
    }

    private fun rule(verdict: FirewallVerdict, destHost: String) = FirewallRule(
        id = "t",
        uid = 10100,
        packageName = "app.test",
        appLabel = "Test",
        destHost = destHost,
        destPort = -1,
        protocol = 6,
        verdict = verdict,
        scope = FirewallRuleScope.SESSION,
    )
}
