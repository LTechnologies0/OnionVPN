package ltechnologies.onionphone.onionvpn.core.tor.control.geo

import java.io.File
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import ltechnologies.onionphone.onionvpn.core.tor.control.TorControlClient
import ltechnologies.onionphone.onionvpn.core.tor.control.protocol.TorControlWire
import timber.log.Timber

/**
 * Resolves circuit hop nicknames → ISO country codes via Tor control
 * (`ns/id` consensus + `ip-to-country`), with a DataDirectory consensus-file
 * fallback when `GETINFO ns/id/…` is unavailable (552) on some embeds.
 *
 * Uses consensus router-status (`ns/id` / cached-*-consensus), not `md/id` —
 * microdescriptors omit OR addresses needed for GeoIP.
 */
class RelayCountryLookup(
    private val control: TorControlClient,
    private val dataDirectory: File? = null,
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
    /** After Tor returns 552 Unrecognized for `ns/id/`, skip further GETINFO ns probes. */
    private val nsIdUnsupported = AtomicBoolean(false)
    private val consensusLock = Any()
    private var consensusIpByIdentityB64: Map<String, String> = emptyMap()
    private var consensusLoadedAtMs: Long = 0L
    private var consensusSourceMtime: Long = -1L

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
        }.onFailure { err ->
            Timber.v("Relay country lookup miss for %s (%s)", fp.take(8), err.message)
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
        if (!nsIdUnsupported.get()) {
            val fromNs = runCatching { lookupRelayIpFromNs(fingerprint) }
                .onFailure { err ->
                    val msg = err.message.orEmpty()
                    if ("552" in msg && "Unrecognized" in msg) {
                        if (nsIdUnsupported.compareAndSet(false, true)) {
                            Timber.d("GETINFO ns/id unsupported — using consensus file fallback")
                        }
                    } else {
                        Timber.v("GETINFO ns/id miss for %s (%s)", fingerprint.take(8), msg)
                    }
                }
                .getOrNull()
            if (!fromNs.isNullOrBlank()) return fromNs
        }
        return lookupRelayIpFromConsensusFile(fingerprint)
    }

    private fun lookupRelayIpFromNs(fingerprint: String): String? {
        val body = control.getInfo("ns/id/$fingerprint")
        return parseRouterStatusAddresses(body)
    }

    private fun lookupRelayIpFromConsensusFile(fingerprint: String): String? {
        val dir = dataDirectory ?: return null
        val identityB64 = fingerprintToIdentityB64(fingerprint) ?: return null
        ensureConsensusIndex(dir)
        return consensusIpByIdentityB64[identityB64]
    }

    private fun ensureConsensusIndex(dir: File) {
        val now = System.currentTimeMillis()
        synchronized(consensusLock) {
            if (now - consensusLoadedAtMs < CONSENSUS_RELOAD_MIN_MS &&
                consensusIpByIdentityB64.isNotEmpty()
            ) {
                return
            }
            val file = CONSENSUS_CANDIDATES
                .map { File(dir, it) }
                .firstOrNull { it.isFile && it.length() > 0 }
                ?: return
            val mtime = file.lastModified()
            if (mtime == consensusSourceMtime && consensusIpByIdentityB64.isNotEmpty()) {
                consensusLoadedAtMs = now
                return
            }
            val map = indexConsensusRelayIps(file.readText())
            consensusIpByIdentityB64 = map
            consensusSourceMtime = mtime
            consensusLoadedAtMs = now
            Timber.v("Consensus relay IP index size=%d from %s", map.size, file.name)
        }
    }

    private fun parseRouterStatusAddresses(body: String): String? {
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
        private const val CONSENSUS_RELOAD_MIN_MS = 30_000L
        private val CONSENSUS_CANDIDATES = listOf(
            "cached-microdesc-consensus",
            "cached-consensus",
        )

        /** Parse Tor consensus `r` lines → identityB64 (no `=`) → IPv4. */
        internal fun indexConsensusRelayIps(text: String): Map<String, String> {
            val map = HashMap<String, String>(8_192)
            for (line in text.lineSequence()) {
                if (!line.startsWith("r ")) continue
                val parts = line.split(Regex("\\s+"))
                // r Nickname IdentityDigest DescriptorDigest Date Time IP ORPort DirPort
                if (parts.size < 7) continue
                val identity = parts[2].trimEnd('=')
                val ip = parts[6]
                if (identity.isNotEmpty() && ip.count { it == '.' } == 3) {
                    map[identity] = ip
                }
            }
            return map
        }

        /** SHA-1 fingerprint hex → Tor consensus IdentityDigest (base64, `=` stripped). */
        internal fun fingerprintToIdentityB64(fingerprint: String): String? {
            val fp = fingerprint.removePrefix("$").uppercase()
            if (fp.length != 40 || fp.any { it !in "0123456789ABCDEF" }) return null
            val bytes = ByteArray(20)
            for (i in 0 until 20) {
                bytes[i] = fp.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
            return Base64.getEncoder().encodeToString(bytes).trimEnd('=')
        }

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
