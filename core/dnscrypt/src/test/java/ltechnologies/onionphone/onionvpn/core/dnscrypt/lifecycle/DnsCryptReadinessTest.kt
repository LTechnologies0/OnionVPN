package ltechnologies.onionphone.onionvpn.core.dnscrypt.lifecycle

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsCryptReadinessTest {
    @Test
    fun listenerHintOnlyNowListening() {
        val (listener, server) = DnsCryptReadiness.hintsFromLogLine(
            "[NOTICE] Now listening to 127.0.0.1:5353",
        )
        assertTrue(listener)
        assertFalse(server)
    }

    @Test
    fun liveServersDoesNotCountAsListener() {
        val (listener, server) = DnsCryptReadiness.hintsFromLogLine(
            "[NOTICE] live servers: 3",
        )
        assertFalse(listener)
        assertTrue(server)
    }

    @Test
    fun liveServersZeroNotReady() {
        val (_, server) = DnsCryptReadiness.hintsFromLogLine("[NOTICE] live servers: 0")
        assertFalse(server)
    }

    @Test
    fun dohOkIsServerHint() {
        val (_, server) = DnsCryptReadiness.hintsFromLogLine(
            "[NOTICE] [cloudflare] OK (DoH) - rtt: 42ms",
        )
        assertTrue(server)
    }

    @Test
    fun dnscryptOkIsServerHint() {
        val (_, server) = DnsCryptReadiness.hintsFromLogLine(
            "[NOTICE] [quad9] OK (DNSCrypt) - rtt: 10ms",
        )
        assertTrue(server)
    }

    @Test
    fun weakNoticeOkMsIsNotServer() {
        val (listener, server) = DnsCryptReadiness.hintsFromLogLine(
            "[NOTICE] netprobe OK in 12ms",
        )
        assertFalse(listener)
        assertFalse(server)
    }

    @Test
    fun waitingForServerClearsHints() {
        val hints = DnsCryptReadiness.hintsFromLogLine(
            "[NOTICE] dnscrypt-proxy is waiting for at least one server to be reachable",
        )
        assertEquals(false to false, hints)
    }
}
