package ltechnologies.onionphone.onionvpn.core.dnscrypt.config

import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsCryptResolverPlanTest {
    @Test
    fun auto_unchanged() {
        val names = DnsCryptResolverPlan.resolvedServerNames(
            DnsCryptPublicResolvers.AUTO,
            TunnelPreferences(),
        )
        assertEquals(listOf(DnsCryptPublicResolvers.AUTO), names)
    }

    @Test
    fun anonymized_filters_incompatible_but_keeps_compatible() {
        val names = DnsCryptResolverPlan.resolvedServerNames(
            "adguard-dns,dnscry.pt-adelaide-ipv4",
            TunnelPreferences(dnsCryptAnonymized = true),
        )
        assertFalse(names.contains("adguard-dns"))
        assertTrue(names.contains("dnscry.pt-adelaide-ipv4"))
    }
}
