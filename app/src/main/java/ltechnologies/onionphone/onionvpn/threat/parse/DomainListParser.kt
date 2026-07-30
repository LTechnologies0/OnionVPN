package ltechnologies.onionphone.onionvpn.threat.parse

import ltechnologies.onionphone.onionvpn.threat.index.DomainReputationIndex
import java.io.BufferedReader
import java.io.Reader

enum class DomainListFormat {
    /** One domain per line (HaGeZi `*-onlydomains.txt`, Yoyo `nohtml`). */
    PLAIN_DOMAINS,
    /** `0.0.0.0 host` / `127.0.0.1 host` hosts file. */
    HOSTS,
    /** Adblock network filters; only simple `||domain^` hostname blocks are kept. */
    ADBLOCK_NETWORK,
}

/**
 * Parses remote blocklist formats into bare hostnames for [DomainReputationIndex].
 */
object DomainListParser {
    /** `||hostname^` with optional `$options` — hostname only, no path. */
    private val ADBLOCK_HOST = Regex(
        """^\|\|([a-z0-9][a-z0-9.-]*[a-z0-9]|[a-z0-9])\^(?:\$([^\#]*))?$""",
        RegexOption.IGNORE_CASE,
    )

    fun parse(reader: Reader, format: DomainListFormat, into: MutableSet<String>): Int {
        val br = reader as? BufferedReader ?: BufferedReader(reader)
        var added = 0
        br.lineSequence().forEach { raw ->
            val line = raw.trim()
            if (line.isEmpty()) return@forEach
            when (format) {
                DomainListFormat.PLAIN_DOMAINS, DomainListFormat.HOSTS -> {
                    if (line.startsWith("#") || line.startsWith("!")) return@forEach
                    // Strip HTML wrappers some endpoints accidentally emit.
                    if (line.startsWith("<") || line.startsWith("</")) return@forEach
                    val domain = extractHostsOrPlain(line) ?: return@forEach
                    if (acceptDomain(domain)) {
                        into.add(domain)
                        added++
                    }
                }
                DomainListFormat.ADBLOCK_NETWORK -> {
                    if (line.startsWith("!") || line.startsWith("[") || line.startsWith("#")) {
                        return@forEach
                    }
                    val domain = extractAdblockHost(line) ?: return@forEach
                    if (acceptDomain(domain)) {
                        into.add(domain)
                        added++
                    }
                }
            }
        }
        return added
    }

    fun extractHostsOrPlain(line: String): String? {
        val domain = when {
            line.startsWith("0.0.0.0 ") || line.startsWith("127.0.0.1 ") ->
                line.substringAfter(' ').trim().substringBefore(' ').trim()
            line.contains(' ') || line.contains('\t') ->
                line.substringAfterLast(' ').trim().ifEmpty {
                    line.substringAfterLast('\t').trim()
                }
            else -> line
        }.trimEnd('.').lowercase()
        return domain.takeIf { it.isNotEmpty() }
    }

    /**
     * Keep whole-host network blocks only.
     * Skips path rules (`||a.com/path`), `removeparam` (would false-positive reddit.com, etc.).
     */
    fun extractAdblockHost(line: String): String? {
        val m = ADBLOCK_HOST.matchEntire(line.trim()) ?: return null
        val host = m.groupValues[1].lowercase().trimEnd('.')
        val options = m.groupValues.getOrNull(2).orEmpty().lowercase()
        if (options.contains("removeparam")) return null
        if (options.contains("rewrite=")) return null
        if (options.contains("redirect=")) return null
        // Path was already rejected by the regex (no `/` before `^`).
        return host
    }

    fun acceptDomain(domain: String): Boolean {
        if (domain.isEmpty() || domain == "localhost") return false
        if (DomainReputationIndex.looksLikeIp(domain)) return false
        if (!domain.any { it == '.' }) return false
        if (domain.any { it <= ' ' || it == '"' || it == '\'' }) return false
        return true
    }
}
