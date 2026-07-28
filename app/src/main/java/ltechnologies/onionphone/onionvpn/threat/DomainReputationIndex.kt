package ltechnologies.onionphone.onionvpn.threat

import java.io.BufferedReader
import java.io.File
import java.io.Reader
import java.util.concurrent.atomic.AtomicReference
import ltechnologies.onionphone.onionvpn.core.model.DomainThreatCategory
import timber.log.Timber

/**
 * In-memory domain blocklists with parent-domain matching.
 *
 * HaGeZi `*-onlydomains.txt` lists are "domains without subdomains": an entry
 * `tracker.example` matches `a.b.tracker.example` and `tracker.example`.
 *
 * Classification priority: [DomainThreatCategory.MALWARE] over
 * [DomainThreatCategory.TRACKING].
 */
class DomainReputationIndex {
    private val malware = AtomicReference<Set<String>>(emptySet())
    private val tracking = AtomicReference<Set<String>>(emptySet())

    fun malwareCount(): Int = malware.get().size
    fun trackingCount(): Int = tracking.get().size

    fun classify(hostname: String?): DomainThreatCategory {
        if (hostname.isNullOrBlank()) return DomainThreatCategory.NONE
        val host = hostname.trim().trimEnd('.').lowercase()
        if (host.isEmpty() || looksLikeIp(host)) return DomainThreatCategory.NONE
        if (matches(malware.get(), host)) return DomainThreatCategory.MALWARE
        if (matches(tracking.get(), host)) return DomainThreatCategory.TRACKING
        return DomainThreatCategory.NONE
    }

    fun replaceMalware(domains: Set<String>) {
        malware.set(domains)
        Timber.i("Domain reputation malware set loaded: %d entries", domains.size)
    }

    fun replaceTracking(domains: Set<String>) {
        tracking.set(domains)
        Timber.i("Domain reputation tracking set loaded: %d entries", domains.size)
    }

    fun loadMalwareFrom(file: File): Boolean = loadInto(file, ::replaceMalware)

    fun loadTrackingFrom(file: File): Boolean = loadInto(file, ::replaceTracking)

    private fun loadInto(file: File, setter: (Set<String>) -> Unit): Boolean {
        if (!file.isFile || file.length() == 0L) return false
        return try {
            val set = HashSet<String>((file.length() / 24).toInt().coerceAtLeast(1_024))
            file.bufferedReader(Charsets.UTF_8).use { parseDomains(it, set) }
            setter(set)
            true
        } catch (error: Exception) {
            Timber.w(error, "Failed to load domain list %s", file.name)
            false
        }
    }

    companion object {
        fun parseDomains(reader: Reader, into: MutableSet<String>): Boolean {
            val br = reader as? BufferedReader ?: BufferedReader(reader)
            var count = 0
            br.lineSequence().forEach { raw ->
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#") || line.startsWith("!")) return@forEach
                // Accept plain domain, or "0.0.0.0 domain" / "127.0.0.1 domain" hosts lines.
                val domain = when {
                    line.startsWith("0.0.0.0 ") || line.startsWith("127.0.0.1 ") ->
                        line.substringAfter(' ').trim().substringBefore(' ').trim()
                    line.contains(' ') || line.contains('\t') ->
                        line.substringAfterLast(' ').trim().ifEmpty {
                            line.substringAfterLast('\t').trim()
                        }
                    else -> line
                }.trimEnd('.').lowercase()
                if (domain.isEmpty() || domain == "localhost" || looksLikeIp(domain)) return@forEach
                if (!domain.any { it == '.' }) return@forEach // skip TLDs-only noise
                into.add(domain)
                count++
            }
            return count > 0
        }

        fun matches(set: Set<String>, hostname: String): Boolean {
            if (set.isEmpty()) return false
            var h = hostname
            while (true) {
                if (set.contains(h)) return true
                val dot = h.indexOf('.')
                if (dot < 0) return false
                h = h.substring(dot + 1)
                // Need at least one more dot for a registrable-looking suffix, but
                // lists may include single-label CDN names — still check them.
                if (h.isEmpty()) return false
            }
        }

        fun looksLikeIp(value: String): Boolean {
            if (value.indexOf(':') >= 0) return true
            var dots = 0
            for (ch in value) {
                when {
                    ch == '.' -> dots++
                    ch !in '0'..'9' -> return false
                }
            }
            return dots == 3
        }
    }
}
