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
        assertEquals(listOf("snowflake a"), MoatCircumventionClient.pickLines(result, null))
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
}
