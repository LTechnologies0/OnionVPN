package ltechnologies.onionphone.onionvpn.core.dnscrypt.kotlin

import java.util.LinkedHashMap

/**
 * In-memory DNS stub cache — mirrors dnscrypt-proxy defaults used in [DnsCryptConfigWriter].
 *
 * Cache key ignores the 16-bit DNS ID (every stub query uses a fresh ID) so hits
 * actually occur across clients; responses are rewritten to the request ID on get.
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
        val key = cacheKey(query) ?: return null
        val e = map[key] ?: return null
        if (System.currentTimeMillis() > e.expiresAtMs) {
            map.remove(key)
            return null
        }
        val out = e.response.copyOf()
        if (query.size >= 2 && out.size >= 2) {
            out[0] = query[0]
            out[1] = query[1]
        }
        return out
    }

    @Synchronized
    fun put(query: ByteArray, response: ByteArray) {
        val key = cacheKey(query) ?: return
        if (response.size < 12) return
        val flags = ((response[2].toInt() and 0xff) shl 8) or (response[3].toInt() and 0xff)
        if (flags and 0x8000 == 0) return // not a response
        val rcode = flags and 0x0f
        // Cache NOERROR + NXDOMAIN; skip SERVFAIL/REFUSED (transient Tor path noise).
        if (rcode != 0 && rcode != 3) return
        val ttl = effectiveTtlSec(response, negative = rcode == 3).coerceIn(
            if (rcode == 3) 10 else minTtlSec,
            if (rcode == 3) 60 else maxTtlSec,
        )
        // Zero ID in stored copy — get() stamps the live query ID.
        val stored = response.copyOf()
        stored[0] = 0
        stored[1] = 0
        map[key] = Entry(
            response = stored,
            expiresAtMs = System.currentTimeMillis() + ttl * 1000L,
        )
    }

    @Synchronized
    fun clear() {
        map.clear()
    }

    /** QNAME + QTYPE + QCLASS — ID-independent. */
    private fun cacheKey(query: ByteArray): String? {
        if (query.size < 13) return null
        var idx = 12
        val labels = StringBuilder()
        while (idx < query.size) {
            val len = query[idx].toInt() and 0xff
            when {
                len == 0 -> {
                    idx++
                    break
                }
                len > 63 || (len and 0xc0) != 0 -> return null
                else -> {
                    idx++
                    if (idx + len > query.size) return null
                    if (labels.isNotEmpty()) labels.append('.')
                    labels.append(String(query, idx, len, Charsets.US_ASCII).lowercase())
                    idx += len
                }
            }
        }
        if (idx + 4 > query.size) return null
        val qtype = ((query[idx].toInt() and 0xff) shl 8) or (query[idx + 1].toInt() and 0xff)
        val qclass = ((query[idx + 2].toInt() and 0xff) shl 8) or (query[idx + 3].toInt() and 0xff)
        return "$labels|$qtype|$qclass"
    }

    private fun effectiveTtlSec(response: ByteArray, negative: Boolean): Int {
        if (negative || response.size < 12) return if (negative) 10 else minTtlSec
        val ancount = ((response[6].toInt() and 0xff) shl 8) or (response[7].toInt() and 0xff)
        if (ancount <= 0) return minTtlSec
        // Skip question; read first answer TTL when layout is simple (no compression jumps in QNAME).
        var idx = 12
        while (idx < response.size) {
            val len = response[idx].toInt() and 0xff
            when {
                len == 0 -> {
                    idx += 5 // 0 + QTYPE + QCLASS
                    break
                }
                (len and 0xc0) == 0xc0 -> {
                    idx += 2 + 4
                    break
                }
                len > 63 -> return minTtlSec
                else -> {
                    idx += 1 + len
                    if (idx > response.size) return minTtlSec
                }
            }
        }
        // Answer name may be a pointer (2 bytes) then TYPE(2) CLASS(2) TTL(4).
        if (idx + 10 > response.size) return minTtlSec
        if ((response[idx].toInt() and 0xc0) == 0xc0) {
            idx += 2
        } else {
            while (idx < response.size) {
                val len = response[idx].toInt() and 0xff
                when {
                    len == 0 -> {
                        idx++
                        break
                    }
                    (len and 0xc0) == 0xc0 -> {
                        idx += 2
                        break
                    }
                    else -> idx += 1 + len
                }
            }
        }
        if (idx + 8 > response.size) return minTtlSec
        idx += 4 // TYPE + CLASS
        val ttl = ((response[idx].toInt() and 0xff) shl 24) or
            ((response[idx + 1].toInt() and 0xff) shl 16) or
            ((response[idx + 2].toInt() and 0xff) shl 8) or
            (response[idx + 3].toInt() and 0xff)
        return if (ttl in 1..maxTtlSec) ttl else minTtlSec
    }
}
