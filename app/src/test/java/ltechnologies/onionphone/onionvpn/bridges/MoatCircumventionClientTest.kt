package ltechnologies.onionphone.onionvpn.bridges

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MoatCircumventionClientTest {
    @Test
    fun pickLines_prefersRequestedTransport() {
        val result = MoatCircumventionClient.Result(
            settings = listOf(
                MoatCircumventionClient.BridgeSetting(
                    type = "snowflake",
                    source = "bridgedb",
                    bridgeStrings = listOf("snowflake a"),
                ),
                MoatCircumventionClient.BridgeSetting(
                    type = "obfs4",
                    source = "bridgedb",
                    bridgeStrings = listOf("obfs4 b", "obfs4 c"),
                ),
            ),
            country = "cn",
            fromDefaults = false,
        )
        assertEquals(listOf("obfs4 b", "obfs4 c"), MoatCircumventionClient.pickLines(result, "obfs4"))
        // No preference → rank by transport (obfs4 before snowflake).
        assertEquals(listOf("obfs4 b", "obfs4 c"), MoatCircumventionClient.pickLines(result, null))
    }

    @Test
    fun pickLines_emptyWhenNone() {
        val result = MoatCircumventionClient.Result(
            settings = emptyList(),
            country = null,
            fromDefaults = true,
        )
        assertTrue(MoatCircumventionClient.pickLines(result, "obfs4").isEmpty())
    }

    @Test
    fun pickLines_prefersBridgedbOverBuiltin() {
        val result = MoatCircumventionClient.Result(
            settings = listOf(
                MoatCircumventionClient.BridgeSetting(
                    type = "obfs4",
                    source = "builtin",
                    bridgeStrings = listOf("obfs4 builtin"),
                ),
                MoatCircumventionClient.BridgeSetting(
                    type = "obfs4",
                    source = "bridgedb",
                    bridgeStrings = listOf("obfs4 fresh"),
                ),
            ),
            country = "at",
            fromDefaults = true,
        )
        assertEquals(listOf("obfs4 fresh", "obfs4 builtin"), MoatCircumventionClient.pickLines(result, "obfs4"))
    }

    @Test
    fun pickLines_nullPrefersObfs4OverWebtunnel() {
        val result = MoatCircumventionClient.Result(
            settings = listOf(
                MoatCircumventionClient.BridgeSetting(
                    type = "webtunnel",
                    source = "bridgedb",
                    bridgeStrings = listOf("webtunnel 192.0.2.1:443 FPR url=https://x.example/"),
                ),
                MoatCircumventionClient.BridgeSetting(
                    type = "obfs4",
                    source = "bridgedb",
                    bridgeStrings = listOf("obfs4 1.2.3.4:443 FPR cert=x iat-mode=0"),
                ),
            ),
            country = null,
            fromDefaults = true,
        )
        assertEquals(
            listOf("obfs4 1.2.3.4:443 FPR cert=x iat-mode=0"),
            MoatCircumventionClient.pickLines(result, null),
        )
    }

    @Test
    fun pickLines_dropsWebtunnelWithoutUrl() {
        val result = MoatCircumventionClient.Result(
            settings = listOf(
                MoatCircumventionClient.BridgeSetting(
                    type = "webtunnel",
                    source = "bridgedb",
                    bridgeStrings = listOf("webtunnel 192.0.2.1:443 FPR"),
                ),
            ),
            country = null,
            fromDefaults = false,
        )
        assertTrue(MoatCircumventionClient.pickLines(result, "webtunnel").isEmpty())
    }
}
