package ltechnologies.onionphone.onionvpn.core.tor.control.geo

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import ltechnologies.onionphone.onionvpn.core.tor.control.TorControlClient
import ltechnologies.onionphone.onionvpn.core.tor.control.protocol.TorControlWire
import timber.log.Timber

/**
 * Resolves circuit hop nicknames → ISO country codes via Tor control
 * (`ns/id` consensus + `ip-to-country`). Requires GeoIPFile in torrc.
 *
 * Uses consensus router-status (`ns/id`), not `desc/id` / `md/id` — only the
 * networkstatus `r`/`a` lines carry OR addresses for GeoIP (control-spec GETINFO).
 */
class RelayCountryLookup(
    private val control: TorControlClient,
) {
    data class Hop(
        val fingerprint: String,
        val nickname: String,
        /** ISO 3166-1 alpha-2 lowercased, or null if unknown. */
        val countryCode: String?,
    )

    /**
     * Fingerprint → ISO cc. ConcurrentHashMap forbids null values, so unknown/miss uses
     * [UNKNOWN_CC] (`""`) as a sentinel after a probe.
     */
    private val countryByFp = ConcurrentHashMap<String, String>()
    private val ipByFp = ConcurrentHashMap<String, String>()
    private val fpAccessOrder = java.util.ArrayDeque<String>()
    private val geoIpAvailable = AtomicBoolean(true)
    private val geoIpProbed = AtomicBoolean(false)

    fun hopsForPath(path: String): List<Hop> {
        if (path.isBlank()) return emptyList()
        return path.split(',').mapNotNull { token ->
            val raw = token.trim()
            if (raw.isEmpty()) return@mapNotNull null
            val fpPart = raw.substringBefore('~').substringBefore('=')
            val nick = raw.substringAfter('~', raw.substringAfter('=', fpPart))
                .takeWhile { it != ' ' }
            val fp = fpPart.removePrefix("$").uppercase()
            if (fp.isEmpty()) return@mapNotNull null
            Hop(
                fingerprint = fp,
                nickname = nick.ifBlank { fp.take(8) },
                countryCode = countryForFingerprint(fp),
            )
        }
    }

    fun countryForFingerprint(fingerprint: String): String? {
        val fp = runCatching { TorControlWire.requireFingerprintHex(fingerprint) }.getOrNull()
            ?: return null
        // Hit (including UNKNOWN_CC sentinel) vs miss (null get).
        countryByFp[fp]?.let { cached ->
            touchFp(fp)
            return cached.ifEmpty { null }
        }
        if (!control.isConnected || !ensureGeoIpAvailable()) {
            countryByFp[fp] = UNKNOWN_CC
            return null
        }
        val cc = runCatching {
            val ip = ipByFp[fp] ?: lookupRelayIp(fp)?.also { ipByFp[fp] = it }
            if (ip.isNullOrBlank()) return@runCatching null
            val raw = control.getInfo("ip-to-country/$ip").trim()
            normalizeCc(raw)
        }.onFailure {
            Timber.d(it, "Relay country lookup failed for %s", fp.take(8))
        }.getOrNull()
        countryByFp[fp] = cc ?: UNKNOWN_CC
        touchFp(fp)
        return cc
    }

    private fun touchFp(fp: String) {
        synchronized(fpAccessOrder) {
            fpAccessOrder.remove(fp)
            fpAccessOrder.addLast(fp)
            while (fpAccessOrder.size > MAX_FP_CACHE) {
                val evict = fpAccessOrder.removeFirst()
                countryByFp.remove(evict)
                ipByFp.remove(evict)
            }
        }
    }

    private fun ensureGeoIpAvailable(): Boolean {
        if (geoIpProbed.get()) return geoIpAvailable.get()
        synchronized(geoIpProbed) {
            if (geoIpProbed.get()) return geoIpAvailable.get()
            val v4 = runCatching { control.getInfo("ip-to-country/ipv4-available") }
                .getOrDefault("0")
                .trim()
            val ok = v4 == "1"
            geoIpAvailable.set(ok)
            geoIpProbed.set(true)
            if (!ok) {
                Timber.d("GeoIP unavailable (ip-to-country/ipv4-available=%s)", v4)
            }
            return ok
        }
    }

    private fun lookupRelayIp(fingerprint: String): String? {
        val body = control.getInfo("ns/id/$fingerprint")
        // Consensus router-status (dir-spec): "r" has IPv4; optional "a" lines have IPv6.
        var ipv4: String? = null
        var ipv6: String? = null
        for (line in body.lineSequence()) {
            val t = line.trim()
            when {
                t.startsWith("r ") -> {
                    val parts = t.split(Regex("\\s+"))
                    if (parts.size >= 7) {
                        val ip = parts[6]
                        if (ip.count { it == '.' } == 3) ipv4 = ip
                    }
                }
                t.startsWith("a ") -> {
                    val addr = t.removePrefix("a ").substringBefore(':').trim()
                    if (addr.contains(':') && ipv6 == null) ipv6 = addr.trim('[', ']')
                }
            }
        }
        return ipv4 ?: ipv6
    }

    private fun normalizeCc(raw: String): String? {
        val cc = raw.trim().lowercase()
        if (cc.length != 2) return null
        if (cc == "??" || cc == "xz") return null
        if (!cc[0].isLetter() || !cc[1].isLetter()) return null
        return cc
    }

    companion object {
        /** Sentinel for “probed, country unknown” — ConcurrentHashMap rejects null values. */
        private const val UNKNOWN_CC = ""
        private const val MAX_FP_CACHE = 4096

        /** ISO alpha-2 → regional-indicator flag emoji. */
        fun flagEmoji(countryCode: String?): String {
            val cc = countryCode?.lowercase() ?: return ""
            if (cc.length != 2) return ""
            val a = Character.codePointAt(cc, 0)
            val b = Character.codePointAt(cc, 1)
            if (a !in 'a'.code..'z'.code || b !in 'a'.code..'z'.code) return ""
            return String(Character.toChars(0x1F1E6 + (a - 'a'.code))) +
                String(Character.toChars(0x1F1E6 + (b - 'a'.code)))
        }
    }
}
