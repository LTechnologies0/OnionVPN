package ltechnologies.onionphone.onionvpn.core.vpn.onionmasq

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.torproject.onionmasq.events.NewConnectionEvent
import org.torproject.onionmasq.events.NewDirectoryEvent
import org.torproject.onionmasq.events.RelayDetails
import java.util.HashMap

class OnionmasqCircuitRepositoryTest {
    @Test
    fun newConnectionStoresCountryCodesAndSurvivesCloseKeyAbsent() {
        val repo = OnionmasqCircuitRepository()
        val event = NewConnectionEvent().apply {
            proxySrc = "10.8.0.2:1234"
            proxyDst = "10.8.0.1:443"
            torDst = "example.com:443"
            appId = 10123
            circuit = listOf(
                RelayDetails().apply { country_code = "NL" },
                RelayDetails().apply { country_code = "DE" },
                RelayDetails().apply { country_code = "US" },
            )
        }
        repo.handleEvent(event)
        assertEquals(listOf("NL", "DE", "US"), repo.countryCodesForAppUid(10123))
        assertEquals(setOf(10123), repo.knownAppUids())
        assertEquals(1, repo.openConnectionsForAppUid(10123).size)
    }

    @Test
    fun directoryEventUpdatesRelaysByCountry() {
        val repo = OnionmasqCircuitRepository()
        val event = NewDirectoryEvent().apply {
            relaysByCountry = HashMap<String, Long>().apply {
                put("FR", 42L)
                put("SE", 17L)
            }
        }
        repo.handleEvent(event)
        assertEquals(42L, repo.relaysByCountry["FR"])
        assertTrue(repo.relaysByCountry.containsKey("SE"))
    }
}
