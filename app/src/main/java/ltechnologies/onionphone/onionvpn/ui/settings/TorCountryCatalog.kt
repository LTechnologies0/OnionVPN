package ltechnologies.onionphone.onionvpn.ui.settings

import java.util.Locale
import ltechnologies.onionphone.onionvpn.core.tor.control.geo.RelayCountryLookup

/**
 * ISO countries + geopolitical / surveillance federations for Tor
 * EntryNodes / ExitNodes / ExcludeNodes (`{cc}` CSV).
 */
object TorCountryCatalog {
    data class Country(val code: String, val name: String) {
        val flag: String get() = RelayCountryLookup.flagEmoji(code)
        val label: String get() = "$flag $name ($code)".trim()
    }

    data class Federation(
        val id: String,
        val label: String,
        val description: String,
        val codes: Set<String>,
    )

    val countries: List<Country> by lazy {
        Locale.getISOCountries()
            .map { cc ->
                val lower = cc.lowercase(Locale.US)
                Country(
                    code = lower,
                    name = Locale("", cc).displayCountry.ifBlank { cc },
                )
            }
            .sortedBy { it.name.lowercase(Locale.US) }
    }

    val federations: List<Federation> = listOf(
        Federation(
            id = "eu",
            label = "European Union (EU)",
            description = "EU member states",
            codes = setOf(
                "at", "be", "bg", "hr", "cy", "cz", "dk", "ee", "fi", "fr", "de", "gr", "hu",
                "ie", "it", "lv", "lt", "lu", "mt", "nl", "pl", "pt", "ro", "sk", "si", "es", "se",
            ),
        ),
        Federation(
            id = "eea",
            label = "European Economic Area (EEA)",
            description = "EU + Iceland, Liechtenstein, Norway",
            codes = setOf(
                "at", "be", "bg", "hr", "cy", "cz", "dk", "ee", "fi", "fr", "de", "gr", "hu",
                "ie", "is", "it", "li", "lv", "lt", "lu", "mt", "nl", "no", "pl", "pt", "ro",
                "sk", "si", "es", "se",
            ),
        ),
        Federation(
            id = "schengen",
            label = "Schengen Area",
            description = "Schengen free-movement zone",
            codes = setOf(
                "at", "be", "bg", "hr", "cz", "dk", "ee", "fi", "fr", "de", "gr", "hu", "is",
                "it", "lv", "li", "lt", "lu", "mt", "nl", "no", "pl", "pt", "ro", "sk", "si",
                "es", "se", "ch",
            ),
        ),
        Federation(
            id = "au",
            label = "African Union (AU)",
            description = "Continental African Union members (common subset)",
            codes = setOf(
                "dz", "ao", "bj", "bw", "bf", "bi", "cm", "cv", "cf", "td", "km", "cg", "cd",
                "ci", "dj", "eg", "gq", "er", "sz", "et", "ga", "gm", "gh", "gn", "gw", "ke",
                "ls", "lr", "ly", "mg", "mw", "ml", "mr", "mu", "ma", "mz", "na", "ne", "ng",
                "rw", "st", "sn", "sc", "sl", "so", "za", "ss", "sd", "tz", "tg", "tn", "ug",
                "zm", "zw",
            ),
        ),
        Federation(
            id = "unasur",
            label = "UNASUR",
            description = "Union of South American Nations",
            codes = setOf(
                "ar", "bo", "br", "cl", "co", "ec", "gy", "py", "pe", "sr", "uy", "ve",
            ),
        ),
        Federation(
            id = "arab_league",
            label = "Arab League",
            description = "League of Arab States",
            codes = setOf(
                "dz", "bh", "km", "dj", "eg", "iq", "jo", "kw", "lb", "ly", "mr", "ma", "om",
                "ps", "qa", "sa", "so", "sd", "sy", "tn", "ae", "ye",
            ),
        ),
        Federation(
            id = "saarc",
            label = "SAARC",
            description = "South Asian Association for Regional Cooperation",
            codes = setOf("af", "bd", "bt", "in", "mv", "np", "pk", "lk"),
        ),
        Federation(
            id = "asean",
            label = "ASEAN",
            description = "Association of Southeast Asian Nations",
            codes = setOf("bn", "kh", "id", "la", "my", "mm", "ph", "sg", "th", "vn"),
        ),
        Federation(
            id = "five_eyes",
            label = "Five Eyes",
            description = "UKUSA surveillance alliance",
            codes = setOf("us", "gb", "ca", "au", "nz"),
        ),
        Federation(
            id = "nine_eyes",
            label = "Nine Eyes",
            description = "Five Eyes + Denmark, France, Netherlands, Norway",
            codes = setOf("us", "gb", "ca", "au", "nz", "dk", "fr", "nl", "no"),
        ),
        Federation(
            id = "fourteen_eyes",
            label = "Fourteen Eyes",
            description = "Nine Eyes + Germany, Belgium, Italy, Spain, Sweden",
            codes = setOf(
                "us", "gb", "ca", "au", "nz", "dk", "fr", "nl", "no",
                "de", "be", "it", "es", "se",
            ),
        ),
    )

    /** Parse Tor `{cc},{cc}` (also tolerates bare `cc`). */
    fun parseNodeCodes(raw: String): Set<String> =
        raw.split(',')
            .map { it.trim().removePrefix("{").removeSuffix("}").lowercase(Locale.US) }
            .filter { it.length == 2 && it.all(Char::isLetter) }
            .toSet()

    /** Encode as Tor StrictNodes country list: `{us},{de}`. */
    fun encodeNodeCodes(codes: Set<String>): String =
        codes.map { it.lowercase(Locale.US) }
            .filter { it.length == 2 }
            .distinct()
            .sorted()
            .joinToString(",") { "{$it}" }

    fun summarize(raw: String): String {
        val codes = parseNodeCodes(raw)
        if (codes.isEmpty()) return "None"
        if (codes.size <= 6) return encodeNodeCodes(codes)
        return "${codes.size} countries"
    }
}
