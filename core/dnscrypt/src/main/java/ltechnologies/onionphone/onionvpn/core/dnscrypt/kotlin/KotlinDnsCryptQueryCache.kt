package ltechnologies.onionphone.onionvpn.core.dnscrypt.kotlin

import java.util.LinkedHashMap

/**
 * In-memory DNS stub cache — mirrors dnscrypt-proxy defaults used in [DnsCryptConfigWriter].
 */
internal class KotlinDnsCryptQueryCache(
    private val maxEntries: Int = 512,
    private val minTtlSec: Int = 120,
    private val maxTtlSec: Int = 1800,
) {
    private data class Entry(val response: ByteArray, val expiresAtMs: Long)

    private val map = object : LinkedHashMap<String, Entry>(maxEntries, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Entry>?): Boolean =
            size > maxEntries
    }

    @Synchronized
    fun get(query: ByteArray): ByteArray? {
        val e = map[cacheKey(query)] ?: return null
        if (System.currentTimeMillis() > e.expiresAtMs) {
            map.remove(cacheKey(query))
            return null
        }
        return e.response
    }

    @Synchronized
    fun put(query: ByteArray, response: ByteArray) {
        val ttl = effectiveTtlSec(response).coerceIn(minTtlSec, maxTtlSec)
        map[cacheKey(query)] = Entry(
            response = response.copyOf(),
            expiresAtMs = System.currentTimeMillis() + ttl * 1000L,
        )
    }

    @Synchronized
    fun clear() {
        map.clear()
    }

    private fun cacheKey(query: ByteArray): String =
        query.contentHashCode().toString() + ":" + query.size

    private fun effectiveTtlSec(response: ByteArray): Int {
        if (response.size < 12) return minTtlSec
        val ancount = ((response[6].toInt() and 0xff) shl 8) or (response[7].toInt() and 0xff)
        if (ancount <= 0) return minTtlSec
        // Best-effort: use first answer TTL if parsable; else default min.
        return minTtlSec
    }
}
