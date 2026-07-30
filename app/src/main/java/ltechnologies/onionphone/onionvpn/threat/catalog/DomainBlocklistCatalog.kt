package ltechnologies.onionphone.onionvpn.threat.catalog

import ltechnologies.onionphone.onionvpn.core.model.DomainThreatCategory
import ltechnologies.onionphone.onionvpn.threat.index.DomainReputationIndex
import ltechnologies.onionphone.onionvpn.threat.parse.DomainListFormat

/**
 * Declarative catalog of remote blocklist feeds that feed the local unified DB.
 *
 * Each source is fetched via Tor probe SOCKS, cached under `sources/`, then merged
 * into `malware.txt` / `tracking.txt` for [DomainReputationIndex].
 */
data class DomainBlocklistSource(
    /** Stable id used as cache filename (`sources/{id}.txt`). */
    val id: String,
    val label: String,
    val category: DomainThreatCategory,
    val format: DomainListFormat,
    /** Prefer first URL; fall through mirrors on failure. */
    val urls: List<String>,
    /**
     * When false, a download failure keeps the previous cache (or skips) and does
     * not fail the whole update if other sources succeeded.
     */
    val required: Boolean = false,
)

object DomainBlocklistCatalog {
    private val HAGEZI_NATIVE_TRACKERS: List<DomainBlocklistSource> = listOf(
        "apple", "amazon", "huawei", "samsung", "xiaomi", "oppo-realme",
        "vivo", "winoffice", "tiktok", "roku", "lgwebos",
    ).map { name ->
        DomainBlocklistSource(
            id = "hagezi-native-$name",
            label = "HaGeZi Native $name",
            category = DomainThreatCategory.TRACKING,
            format = DomainListFormat.PLAIN_DOMAINS,
            urls = listOf(
                "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.$name-onlydomains.txt",
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.$name-onlydomains.txt",
            ),
        )
    }

    val ALL: List<DomainBlocklistSource> = listOf(
        // --- Malware / C2 / phishing ---
        DomainBlocklistSource(
            id = "hagezi-tif-mini",
            label = "HaGeZi TIF mini",
            category = DomainThreatCategory.MALWARE,
            format = DomainListFormat.PLAIN_DOMAINS,
            required = true,
            urls = listOf(
                "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
                "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/tif.mini-onlydomains.txt",
            ),
        ),
        DomainBlocklistSource(
            id = "urlhaus-hosts",
            label = "URLhaus (malware-filter hosts)",
            category = DomainThreatCategory.MALWARE,
            format = DomainListFormat.HOSTS,
            urls = listOf(
                "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt",
                "https://curbengh.github.io/malware-filter/urlhaus-filter-hosts-online.txt",
                "https://malware-filter.pages.dev/urlhaus-filter-hosts-online.txt",
                "https://urlhaus-filter.pages.dev/urlhaus-filter-hosts-online.txt",
            ),
        ),
        DomainBlocklistSource(
            id = "uassets-badware",
            label = "uBlock uAssets badware",
            category = DomainThreatCategory.MALWARE,
            format = DomainListFormat.ADBLOCK_NETWORK,
            urls = listOf(
                "https://cdn.jsdelivr.net/gh/uBlockOrigin/uAssets@master/filters/badware.txt",
                "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
            ),
        ),
        // --- Ads / tracking / telemetry ---
        DomainBlocklistSource(
            id = "hagezi-light",
            label = "HaGeZi Light",
            category = DomainThreatCategory.TRACKING,
            format = DomainListFormat.PLAIN_DOMAINS,
            required = true,
            urls = listOf(
                "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt",
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
                "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/light-onlydomains.txt",
            ),
        ),
        DomainBlocklistSource(
            id = "yoyo-adservers",
            label = "Peter Lowe / Yoyo adservers",
            category = DomainThreatCategory.TRACKING,
            format = DomainListFormat.HOSTS,
            urls = listOf(
                // Semicolon separators are required by this endpoint (HTML wrapper otherwise).
                "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts;showintro=0",
                "https://pgl.yoyo.org/as/serverlist.php?hostformat=hosts;showintro=0",
            ),
        ),
        DomainBlocklistSource(
            id = "uassets-privacy",
            label = "uBlock uAssets privacy",
            category = DomainThreatCategory.TRACKING,
            format = DomainListFormat.ADBLOCK_NETWORK,
            urls = listOf(
                "https://cdn.jsdelivr.net/gh/uBlockOrigin/uAssets@master/filters/privacy.txt",
                "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
            ),
        ),
    ) + HAGEZI_NATIVE_TRACKERS

    fun malwareSources(): List<DomainBlocklistSource> =
        ALL.filter { it.category == DomainThreatCategory.MALWARE }

    fun trackingSources(): List<DomainBlocklistSource> =
        ALL.filter { it.category == DomainThreatCategory.TRACKING }
}
