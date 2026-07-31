package ltechnologies.onionphone.onionvpn.core.vpn.dns

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints

/**
 * App-side Automap for engines without Tor `AutomapHostsOnResolve` (Arti).
 *
 * Allocates stable virtual IPv4 addresses in Tor's `10.192.0.0/10` pool so
 * [SocksUidBridge] can rewrite CONNECT literals back to `.onion` / `.exit`
 * hostnames via [DnsHostnameCache] (SOCKS5A).
 */
object OnionAutomapAllocator {
    /** Base `10.192.0.0` — same pool as C Tor VirtualAddrNetwork. */
    private const val BASE = 0x0AC00000
    /** 22 host bits in a /10. Skip .0 for clarity. */
    private const val HOST_MASK = 0x003FFFFF

    private val nextHost = AtomicInteger(1)
    private val hostByName = ConcurrentHashMap<String, String>(256)

    fun ipv4ForHostname(hostname: String): String {
        val key = hostname.trim().trimEnd('.').lowercase()
        require(TunnelEndpoints.isOnionLikeHostname(key)) { "not onion-like: $hostname" }
        return hostByName.computeIfAbsent(key) {
            val host = nextHost.getAndIncrement() and HOST_MASK
            val safeHost = if (host == 0) 1 else host
            val ipInt = BASE or safeHost
            val ip = formatIpv4(ipInt)
            DnsHostnameCache.put(ip, key)
            ip
        }
    }

    fun clear() {
        hostByName.clear()
        nextHost.set(1)
    }

    private fun formatIpv4(ipInt: Int): String =
        "${(ipInt ushr 24) and 0xff}." +
            "${(ipInt ushr 16) and 0xff}." +
            "${(ipInt ushr 8) and 0xff}." +
            "${ipInt and 0xff}"
}
