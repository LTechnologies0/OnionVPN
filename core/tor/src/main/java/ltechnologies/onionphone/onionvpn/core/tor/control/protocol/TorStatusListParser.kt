package ltechnologies.onionphone.onionvpn.core.tor.control.protocol

import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorCircuitInfo
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorStreamInfo

/**
 * Parses GETINFO circuit-status / stream-status multiline bodies (control-spec).
 */
object TorStatusListParser {

    fun parseCircuitStatus(body: String): List<TorCircuitInfo> =
        body.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .mapNotNull { parseCircuitLine(it) }
            .toList()

    fun parseStreamStatus(body: String): List<TorStreamInfo> =
        body.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .mapNotNull { parseStreamLine(it) }
            .toList()

    fun parseCircuitLine(line: String): TorCircuitInfo? {
        val parts = tokenize(line)
        if (parts.size < 2) return null
        val id = parts[0]
        val status = parts[1]
        val path = parts.getOrNull(2)?.takeIf { !it.contains('=') }.orEmpty()
        return TorCircuitInfo(
            id = id,
            status = status,
            path = path,
            purpose = kv(parts, "PURPOSE").orEmpty(),
            buildFlags = kv(parts, "BUILD_FLAGS").orEmpty(),
            socksUsername = kvQuoted(parts, "SOCKS_USERNAME"),
            socksPassword = kvQuoted(parts, "SOCKS_PASSWORD"),
            timeCreated = kv(parts, "TIME_CREATED"),
            hsState = kv(parts, "HS_STATE"),
            reason = kv(parts, "REASON"),
        )
    }

    fun parseStreamLine(line: String): TorStreamInfo? {
        val parts = tokenize(line)
        if (parts.size < 4) return null
        return TorStreamInfo(
            id = parts[0],
            status = parts[1],
            circuitId = parts[2],
            target = parts[3],
            sourceAddr = kv(parts, "SOURCE_ADDR"),
            purpose = kv(parts, "PURPOSE"),
            socksUsername = kvQuoted(parts, "SOCKS_USERNAME"),
            socksPassword = kvQuoted(parts, "SOCKS_PASSWORD"),
            clientProtocol = kv(parts, "CLIENT_PROTOCOL"),
            reason = kv(parts, "REASON"),
        )
    }

    /** Split on spaces but keep KEY="quoted value" as one token. */
    fun tokenize(line: String): List<String> {
        val out = ArrayList<String>()
        var i = 0
        while (i < line.length) {
            while (i < line.length && line[i].isWhitespace()) i++
            if (i >= line.length) break
            if (line[i] == '"') {
                i++
                val start = i
                while (i < line.length && line[i] != '"') i++
                out.add(line.substring(start, i))
                if (i < line.length) i++
                continue
            }
            val start = i
            while (i < line.length && !line[i].isWhitespace()) {
                if (line[i] == '=' && i + 1 < line.length && line[i + 1] == '"') {
                    // KEY="value"
                    i += 2
                    while (i < line.length && line[i] != '"') i++
                    if (i < line.length) i++
                    break
                }
                i++
            }
            out.add(line.substring(start, i))
        }
        return out
    }

    fun kv(parts: List<String>, key: String): String? =
        parts.firstOrNull { it.startsWith("$key=") }?.substringAfter('=')?.trim('"')

    fun kvQuoted(parts: List<String>, key: String): String? = kv(parts, key)
}
