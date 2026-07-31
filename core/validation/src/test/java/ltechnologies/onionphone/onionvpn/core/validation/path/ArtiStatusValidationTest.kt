package ltechnologies.onionphone.onionvpn.core.validation.path

import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ArtiStatusValidationTest {
    @Test
    fun readyStatus_passes() {
        val status = """
            engine=arti
            version=arti-mobile
            ready=1
            socks=12345
            dns=12346
            shared_socks=1
            bridges=0
            pt=
            synthesize_onion_automap=1
        """.trimIndent()
        val check = TorPathValidator.validateArtiStatusContent(
            status,
            source = "arti.status",
            socksPort = 12345,
            dnsPort = 12346,
        )
        assertEquals(ValidationStatus.Pass, check.status)
        assertEquals("tor.arti.status", check.id)
    }

    @Test
    fun notReady_failsHard() {
        val status = """
            engine=arti
            ready=0
            socks=1
            dns=2
            shared_socks=1
            synthesize_onion_automap=1
        """.trimIndent()
        val check = TorPathValidator.validateArtiStatusContent(status, "arti.status")
        assertEquals(ValidationStatus.Fail, check.status)
        assertTrue(check.tripsKillSwitch)
    }
}
