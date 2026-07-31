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
            .map { normalizeBridgeLine(it) }
            .toList()

    fun isConfigured(bridgeText: String): Boolean = parseLines(bridgeText).isNotEmpty()

    /**
     * Lyrebird webtunnel defaults to `utls=hellorandomizednoalpn`. On Android that ClientHello
     * is frequently rejected by Moat HTTPS fronts (`remote error: tls: protocol version not
     * supported`) while Go/stdlib TLS to the same host succeeds. Inject `utls=none` so
     * lyrebird uses plain crypto/tls ([webtunnel client.go](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird)).
     *
     * Also rewrite Moat documentation ORPorts (`2001:db8:` / learned IPv4) to TBA-style
     * `192.0.2.x:443` and set `addr=<url-host>:<port>` so Tor dials only via the HTTPS front
     * and does not Prefer a direct IPv4 ORPort from the bridge descriptor.
     */
    fun normalizeBridgeLine(line: String): String {
        val trimmed = line.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("#")) return trimmed
        val hadBridgePrefix = trimmed.startsWith("Bridge ", ignoreCase = true)
        val body = trimmed
            .removePrefix("Bridge ")
            .removePrefix("bridge ")
            .trim()
        if (!body.startsWith("webtunnel", ignoreCase = true)) return trimmed
        if (!body.contains("url=", ignoreCase = true)) return trimmed

        val tokens = body.split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (tokens.size < 2) return trimmed

        val fingerprint = tokens.getOrNull(2)
            ?.takeIf { FINGERPRINT_HEX.matches(it) }
        val argTokens = tokens.drop(if (fingerprint != null) 3 else 2)
            .filterNot { it.substringBefore('=').equals("addr", ignoreCase = true) }
            .toMutableList()

        val urlValue = Regex("""(?i)\burl=(\S+)""").find(body)?.groupValues?.getOrNull(1)
            ?: return trimmed
        val urlHostPort = urlToTcpEndpoint(urlValue) ?: return trimmed

        val fpKey = fingerprint ?: urlValue
        val octet = (fpKey.hashCode().ushr(1) % 254) + 1
        val placeholder = "192.0.2.$octet:443"

        val hasUtls = argTokens.any { it.startsWith("utls=", ignoreCase = true) }
        when {
            !hasUtls -> argTokens += "utls=none"
            else -> {
                val idx = argTokens.indexOfFirst { it.startsWith("utls=", ignoreCase = true) }
                val value = argTokens[idx].substringAfter('=')
                if (value.lowercase() in BROKEN_WEBTUNNEL_UTLS) {
                    argTokens[idx] = "utls=none"
                }
            }
        }
        if (argTokens.none { it.startsWith("addr=", ignoreCase = true) }) {
            argTokens += "addr=$urlHostPort"
        }

        val rebuilt = buildString {
            append("webtunnel ")
            append(placeholder)
            if (fingerprint != null) {
                append(' ')
                append(fingerprint)
            }
            argTokens.forEach { arg ->
                append(' ')
                append(arg)
            }
        }
        return if (hadBridgePrefix) "Bridge $rebuilt" else rebuilt
    }

    private fun urlToTcpEndpoint(urlValue: String): String? {
        return try {
            val uri = java.net.URI(urlValue)
            val host = uri.host?.trim().orEmpty()
            if (host.isEmpty()) return null
            val port = uri.port.takeIf { it > 0 } ?: when (uri.scheme?.lowercase()) {
                "http" -> 80
                else -> 443
            }
            if (host.contains(':') && !host.startsWith('[')) {
                "[$host]:$port"
            } else {
                "$host:$port"
            }
        } catch (_: Exception) {
            null
        }
    }

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

    private val FINGERPRINT_HEX = Regex("""^[0-9A-Fa-f]{40}$""")

    /** Randomized uTLS fingerprints that Moat WebTunnel fronts reject on our Lyrebird build. */
    private val BROKEN_WEBTUNNEL_UTLS = setOf(
        "hellorandomized",
        "hellorandomizedalpn",
        "hellorandomizednoalpn",
    )

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
