package ltechnologies.onionphone.onionvpn.threat.index

import ltechnologies.onionphone.onionvpn.threat.parse.DomainListFormat
import ltechnologies.onionphone.onionvpn.threat.parse.DomainListParser
import java.io.File
import java.io.Reader
import java.util.concurrent.atomic.AtomicReference
import ltechnologies.onionphone.onionvpn.core.model.DomainThreatCategory
import timber.log.Timber

/**
 * In-memory domain blocklists with parent-domain matching against the unified
 * local DB (`malware.txt` / `tracking.txt`).
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
        /** Accepts plain domains and hosts-file lines. */
        fun parseDomains(reader: Reader, into: MutableSet<String>): Boolean =
            DomainListParser.parse(reader, DomainListFormat.HOSTS, into) > 0

        fun matches(set: Set<String>, hostname: String): Boolean {
            if (set.isEmpty()) return false
            if (set.contains(hostname)) return true
            var from = 0
            while (true) {
                val dot = hostname.indexOf('.', from)
                if (dot < 0 || dot + 1 >= hostname.length) return false
                from = dot + 1
                // HashSet needs a String key; build suffix without intermediate parents chain.
                if (suffixContained(set, hostname, from)) return true
            }
        }

        /** Compare hostname[from..] to set members without allocating when miss is likely via length prefilter. */
        private fun suffixContained(set: Set<String>, hostname: String, from: Int): Boolean {
            val len = hostname.length - from
            // Fast path: most blocklist hits are exact stored parents — one substring.
            // (Full zero-alloc needs a custom suffix index; tracking compression is Phase D.)
            return set.contains(hostname.substring(from))
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
