package ltechnologies.onionphone.onionvpn.core.vpn.onionmasq

import java.util.concurrent.ConcurrentHashMap
import org.torproject.onionmasq.circuit.CircuitCountryCodes
import org.torproject.onionmasq.events.ClosedConnectionEvent
import org.torproject.onionmasq.events.FailedConnectionEvent
import org.torproject.onionmasq.events.NewConnectionEvent
import org.torproject.onionmasq.events.NewDirectoryEvent
import org.torproject.onionmasq.events.OnionmasqEvent
import org.torproject.onionmasq.events.RelayDetails

/**
 * Tor-VPN-style circuit aggregation keyed by Android UID (mirrors onionmasq CircuitStore).
 *
 * Country codes for an app are retained after sockets close so the UI can still show hops.
 */
class OnionmasqCircuitRepository {
    data class ProxyKey(val src: String, val dst: String)

    data class OpenConnection(
        val appId: Int,
        val torDst: String,
        val circuit: List<RelayDetails>,
    )

    private val openByApp = ConcurrentHashMap<Int, MutableSet<ProxyKey>>()
    private val connections = ConcurrentHashMap<ProxyKey, OpenConnection>()
    private val countryCodesByApp = ConcurrentHashMap<Int, List<String>>()
    @Volatile
    var relaysByCountry: Map<String, Long> = emptyMap()
        private set

    fun reset() {
        openByApp.clear()
        connections.clear()
        countryCodesByApp.clear()
        relaysByCountry = emptyMap()
    }

    fun handleEvent(event: OnionmasqEvent) {
        when (event) {
            is NewConnectionEvent -> onNew(event)
            is ClosedConnectionEvent -> onClosed(event.proxySrc, event.proxyDst)
            is FailedConnectionEvent -> onClosed(event.proxySrc, event.proxyDst)
            is NewDirectoryEvent -> {
                relaysByCountry = event.relaysByCountry?.toMap() ?: emptyMap()
            }
            else -> Unit
        }
    }

    fun knownAppUids(): Set<Int> =
        (countryCodesByApp.keys + openByApp.keys).toSet()

    fun countryCodesForAppUid(uid: Int): List<String> =
        countryCodesByApp[uid].orEmpty()

    fun circuitCountryCodesForAppUid(uid: Int): CircuitCountryCodes? {
        val codes = countryCodesForAppUid(uid)
        if (codes.isEmpty()) return null
        return CircuitCountryCodes(ArrayList(codes))
    }

    fun openConnectionsForAppUid(uid: Int): List<OpenConnection> {
        val keys = openByApp[uid] ?: return emptyList()
        return keys.mapNotNull { connections[it] }
    }

    fun removeCountryCodes(uid: Int) {
        countryCodesByApp.remove(uid)
    }

    private fun onNew(event: NewConnectionEvent) {
        val key = ProxyKey(event.proxySrc, event.proxyDst)
        val conn = OpenConnection(
            appId = event.appId,
            torDst = event.torDst,
            circuit = event.circuit.orEmpty(),
        )
        connections[key] = conn
        openByApp.getOrPut(event.appId) { ConcurrentHashMap.newKeySet() }.add(key)
        val codes = conn.circuit.mapNotNull { it.country_code?.takeIf { c -> c.isNotBlank() } }
        if (codes.isNotEmpty()) {
            countryCodesByApp[event.appId] = codes
        }
    }

    private fun onClosed(proxySrc: String?, proxyDst: String?) {
        if (proxySrc == null || proxyDst == null) return
        val key = ProxyKey(proxySrc, proxyDst)
        val removed = connections.remove(key) ?: return
        openByApp[removed.appId]?.remove(key)
        // Keep countryCodesByApp for UI (Tor VPN CircuitStore behavior).
    }
}
