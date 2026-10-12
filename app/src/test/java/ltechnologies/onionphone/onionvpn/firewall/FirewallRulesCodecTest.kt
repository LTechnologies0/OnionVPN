package ltechnologies.onionphone.onionvpn.firewall

import ltechnologies.onionphone.onionvpn.core.model.FirewallRule
import ltechnologies.onionphone.onionvpn.core.model.FirewallRuleScope
import ltechnologies.onionphone.onionvpn.core.model.FirewallVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class FirewallRulesCodecTest {
    @Test
    fun decode_skipsCorruptItem_keepsSiblings() {
        val good = FirewallRule(
            id = "good",
            uid = 10123,
            packageName = "app.good",
            appLabel = "Good",
            destHost = "1.2.3.4",
            destPort = 443,
            protocol = 6,
            verdict = FirewallVerdict.ALLOW_TOR,
            scope = FirewallRuleScope.SESSION,
        )
        val json = """[
            ${FirewallRulesCodec.encodeRules(listOf(good)).removePrefix("[").removeSuffix("]")},
            {"id":"bad","uid":"not-an-int"}
        ]"""
        val decoded = FirewallRulesCodec.decodeRules(json)
        assertTrue(decoded is FirewallRulesCodec.DecodeResult.Ok)
        assertEquals(listOf("good"), decoded.rules.map { it.id })
    }

    @Test
    fun decode_wholeListFailure_onUnreadableArray() {
        val decoded = FirewallRulesCodec.decodeRules("{not-an-array}")
        assertTrue(decoded is FirewallRulesCodec.DecodeResult.WholeListFailure)
        assertTrue(decoded.rules.isEmpty())
    }

    @Test
    fun decode_blank_isEmptyOk() {
        val decoded = FirewallRulesCodec.decodeRules("  ")
        assertTrue(decoded is FirewallRulesCodec.DecodeResult.Ok)
        assertTrue(decoded.rules.isEmpty())
    }
}
