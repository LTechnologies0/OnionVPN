package ltechnologies.onionphone.onionvpn.core.validation.path

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import ltechnologies.onionphone.onionvpn.core.tor.config.TorConfigWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TorPathValidatorContentTest {
    @Test
    fun generatedTorrc_passes() {
        val torrc = TorConfigWriter.write(
            dataDirectory = "/data/local/tmp/onionvpn-tor",
            socksPort = 19_050,
            dnsCryptSocksPort = 19_051,
            probeSocksPort = 19_052,
            dnsPort = 19_053,
        )
        val check = TorPathValidator.validateTorrcContent(
            config = torrc,
            source = "generated",
            socksPort = 19_050,
            dnsPort = 19_053,
        )
        assertEquals(check.detail, ValidationStatus.Pass, check.status)
        assertTrue(torrc.contains("MaxClientCircuitsPending 96"))
    }

    @Test
    fun strippedIsolation_fails() {
        val torrc = TorConfigWriter.write(dataDirectory = "/tmp/t")
            .replace("IsolateSOCKSAuth", "IsolateNowhere")
        val check = TorPathValidator.validateTorrcContent(torrc, source = "stripped")
        assertEquals(ValidationStatus.Fail, check.status)
    }

    @Test
    fun wrongPendingCount_fails() {
        val torrc = TorConfigWriter.write(dataDirectory = "/tmp/t")
            .replace("MaxClientCircuitsPending 96", "MaxClientCircuitsPending 1")
        val check = TorPathValidator.validateTorrcContent(torrc, source = "pending")
        assertEquals(ValidationStatus.Fail, check.status)
        assertTrue(check.detail.contains("pendingOk=false"))
    }

    @Test
    fun missingSocksPort_fails() {
        val torrc = TorConfigWriter.write(
            dataDirectory = "/tmp/t",
            socksPort = 19_050,
            dnsPort = 19_053,
        )
        val check = TorPathValidator.validateTorrcContent(
            config = torrc,
            source = "ports",
            socksPort = 1,
            dnsPort = 19_053,
        )
        assertEquals(ValidationStatus.Fail, check.status)
        assertTrue(check.detail.contains("socks=false"))
    }

    @Test
    fun loopbackEndpoints_areDocumentationSafe() {
        assertEquals("127.0.0.1", TunnelEndpoints.LOOPBACK)
        assertEquals("192.0.2.1", TunnelEndpoints.FALLBACK_BLOCKING_DNS)
    }
}
