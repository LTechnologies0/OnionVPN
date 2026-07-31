package ltechnologies.onionphone.onionvpn.core.tor.config

import java.io.File

/**
 * Parses user bridge lines and emits `UseBridges` / `ClientTransportPlugin` / `Bridge`
 * for torrc — full Tor Browser Android PT surface:
 *
 * - [libLyrebird.so] — meek_lite, obfs2/3/4, scramblesuit, webtunnel, snowflake
 * - [libConjure.so] — conjure (+ refraction register URL)
 *
 * Fallback (if Lyrebird absent): [libobfs4proxy.so] / [libsnowflake.so].
 */
object TorBridgeConfig {
    const val LIB_LYREBIRD = "libLyrebird.so"
    const val LIB_CONJURE = "libConjure.so"
    const val LIB_OBFS4PROXY = "libobfs4proxy.so"
    const val LIB_SNOWFLAKE = "libsnowflake.so"

    const val CONJURE_REGISTER_URL = "https://registration.refraction.network/api"

    /** Transports provided by lyrebird (Tor Browser `torrc-defaults`). */
    val LYREBIRD_TRANSPORTS = setOf(
        "obfs2", "obfs3", "obfs4", "scramblesuit", "meek_lite", "webtunnel", "snowflake",
    )

    private val OBFS4PROXY_TRANSPORTS = setOf(
        "obfs2", "obfs3", "obfs4", "scramblesuit", "meek_lite", "webtunnel",
    )

    fun parseLines(bridgeText: String): List<String> =
        bridgeText.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .toList()

    fun isConfigured(bridgeText: String): Boolean = parseLines(bridgeText).isNotEmpty()

    fun transportOf(line: String): String? {
        val body = line
            .removePrefix("Bridge ")
            .removePrefix("bridge ")
            .trim()
        if (body.isEmpty()) return null
        if (body.startsWith("ClientTransportPlugin ", ignoreCase = true)) return null
        val first = body.substringBefore(' ')
        if (first.contains('.') || first.contains(':') || first.startsWith('[')) {
            return null
        }
        return first.lowercase()
    }

    fun requiredTransports(bridgeText: String): Set<String> =
        parseLines(bridgeText).mapNotNull { transportOf(it) }.toSet()

    fun libFile(nativeLibraryDir: File, name: String): File? =
        File(nativeLibraryDir, name).takeIf { it.isFile && it.length() > 0L }

    fun binaryForTransport(transport: String, nativeLibraryDir: File): File? {
        val t = transport.lowercase()
        return when (t) {
            "conjure" -> libFile(nativeLibraryDir, LIB_CONJURE)
            in LYREBIRD_TRANSPORTS -> {
                libFile(nativeLibraryDir, LIB_LYREBIRD)
                    ?: when (t) {
                        "snowflake" -> libFile(nativeLibraryDir, LIB_SNOWFLAKE)
                        in OBFS4PROXY_TRANSPORTS -> libFile(nativeLibraryDir, LIB_OBFS4PROXY)
                        else -> null
                    }
            }
            else -> null
        }
    }

    /**
     * ClientTransportPlugin lines for shipped PT binaries (Tor Browser Android layout).
     * When bridges are enabled, registers the full available PT set so any paste works.
     */
    fun clientTransportPluginLines(
        bridgeText: String,
        nativeLibraryDir: File,
    ): List<String> {
        val needed = requiredTransports(bridgeText)
        val unknown = needed - LYREBIRD_TRANSPORTS - setOf("conjure")
        if (unknown.isNotEmpty()) {
            error("Unsupported bridge transport(s): $unknown")
        }
        needed.forEach { t ->
            binaryForTransport(t, nativeLibraryDir)
                ?: error("Missing pluggable-transport binary for '$t' under $nativeLibraryDir")
        }

        val lines = mutableListOf<String>()
        val lyrebird = libFile(nativeLibraryDir, LIB_LYREBIRD)
        if (lyrebird != null) {
            lines += "ClientTransportPlugin meek_lite,obfs2,obfs3,obfs4,scramblesuit,webtunnel exec ${lyrebird.absolutePath}"
            lines += "ClientTransportPlugin snowflake exec ${lyrebird.absolutePath}"
        } else {
            val obfs = needed.filter { it in OBFS4PROXY_TRANSPORTS }.sorted()
            if (obfs.isNotEmpty()) {
                val bin = libFile(nativeLibraryDir, LIB_OBFS4PROXY)
                    ?: error("Missing $LIB_OBFS4PROXY")
                lines += "ClientTransportPlugin ${obfs.joinToString(",")} exec ${bin.absolutePath}"
            }
            if ("snowflake" in needed) {
                val bin = libFile(nativeLibraryDir, LIB_SNOWFLAKE)
                    ?: error("Missing $LIB_SNOWFLAKE")
                lines += "ClientTransportPlugin snowflake exec ${bin.absolutePath}"
            }
        }

        val conjure = libFile(nativeLibraryDir, LIB_CONJURE)
        if (conjure != null) {
            lines += "ClientTransportPlugin conjure exec ${conjure.absolutePath} -registerURL $CONJURE_REGISTER_URL"
        } else if ("conjure" in needed) {
            error("Missing $LIB_CONJURE for conjure")
        }
        return lines
    }

    fun torrcFragment(
        bridgeText: String,
        nativeLibraryDir: File?,
    ): String {
        val lines = parseLines(bridgeText)
        if (lines.isEmpty()) return ""
        return buildString {
            appendLine("UseBridges 1")
            if (nativeLibraryDir != null) {
                clientTransportPluginLines(bridgeText, nativeLibraryDir).forEach { appendLine(it) }
            }
            lines.forEach { line ->
                when {
                    line.startsWith("ClientTransportPlugin ", ignoreCase = true) -> Unit
                    line.startsWith("Bridge ", ignoreCase = true) -> appendLine(line)
                    else -> appendLine("Bridge $line")
                }
            }
        }
    }
}
