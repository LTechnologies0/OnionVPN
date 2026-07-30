package ltechnologies.onionphone.onionvpn.core.tor.control.ops

import java.io.IOException
import ltechnologies.onionphone.onionvpn.core.tor.control.catalog.TorControlCatalog
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorCircuitInfo
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorStreamInfo
import ltechnologies.onionphone.onionvpn.core.tor.control.protocol.TorControlReplyParser
import ltechnologies.onionphone.onionvpn.core.tor.control.protocol.TorControlWire
import ltechnologies.onionphone.onionvpn.core.tor.control.protocol.TorStatusListParser
import ltechnologies.onionphone.onionvpn.core.tor.control.transport.TorControlTransport

/**
 * Package `control.ops` — high-level control-spec operations over an open transport.
 *
 * Imported by [ltechnologies.onionphone.onionvpn.core.tor.control.TorControlClient] only.
 * Uses [TorControlCatalog] wire names; does not own connection lifecycle.
 */

/**
 * Typed Tor control operations (SIGNAL, GETINFO, SETCONF, RESOLVE, …).
 *
 * @param transport open LocalSocket channel
 * @param refreshInfo callback to re-poll GETINFO health keys into status
 */
internal class TorControlOperations(
    private val transport: TorControlTransport,
    private val refreshInfo: () -> Unit,
) {
    @Volatile
    private var lastNewNymMs: Long = 0L

    fun signal(name: String): Result<Unit> = runCatching {
        transport.command("SIGNAL $name")
        Unit
    }

    fun signal(signal: TorControlCatalog.Signal): Result<Unit> = signal(signal.wire)

    /**
     * SIGNAL NEWNYM only — control-spec already clears the client DNS cache with NEWNYM;
     * a follow-up CLEARDNSCACHE is redundant.
     */
    fun newNym(): Result<Unit> = signal(TorControlCatalog.Signal.NEWNYM)

    /**
     * Rate-limited NEWNYM (control-spec: Tor MAY rate-limit; ~10s → 551 in practice).
     * @return failure with message if called too soon
     */
    fun newNymRateLimited(minIntervalMs: Long = NEWNYM_MIN_INTERVAL_MS): Result<Unit> {
        val now = System.currentTimeMillis()
        val wait = lastNewNymMs + minIntervalMs - now
        if (wait > 0) {
            return Result.failure(
                IOException("NEWNYM rate-limited — wait ${((wait + 999) / 1000)}s (Tor ~10s)"),
            )
        }
        return newNym().also { result ->
            if (result.isSuccess) lastNewNymMs = System.currentTimeMillis()
        }
    }

    fun clearDnsCache(): Result<Unit> = signal(TorControlCatalog.Signal.CLEARDNSCACHE)

    fun setActive(): Result<Unit> = signal(TorControlCatalog.Signal.ACTIVE)

    fun setDormant(): Result<Unit> = signal(TorControlCatalog.Signal.DORMANT)

    fun reload(): Result<Unit> = signal(TorControlCatalog.Signal.RELOAD)

    fun heartbeat(): Result<Unit> = signal(TorControlCatalog.Signal.HEARTBEAT)

    fun dropGuards(): Result<Unit> = runCatching {
        transport.command("DROPGUARDS")
        Unit
    }

    fun dropTimeouts(): Result<Unit> = runCatching {
        transport.command("DROPTIMEOUTS")
        Unit
    }

    fun setDisableNetwork(disabled: Boolean): Result<Unit> = runCatching {
        transport.command("SETCONF DisableNetwork=${if (disabled) 1 else 0}")
        if (!disabled) setActive()
        Unit
    }

    /** Live SETCONF for circuit timing (no Tor restart). */
    fun setCircuitTiming(
        maxCircuitDirtinessSec: Int,
        newCircuitPeriodSec: Int,
    ): Result<Unit> = runCatching {
        val dirt = maxCircuitDirtinessSec.coerceIn(60, 7_200)
        val period = newCircuitPeriodSec.coerceIn(10, 3_600)
        transport.command("SETCONF MaxCircuitDirtiness=$dirt NewCircuitPeriod=$period")
        Unit
    }

    /** Apply bridge lines live (replaces Bridge config group). */
    fun setBridges(bridgeLines: List<String>): Result<Unit> = runCatching {
        val cleaned = bridgeLines.map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
        if (cleaned.isEmpty()) {
            transport.command("SETCONF UseBridges=0")
            transport.command("RESETCONF Bridge")
        } else {
            val bridges = cleaned.joinToString(" ") { line ->
                val v = if (line.startsWith("Bridge ", ignoreCase = true)) {
                    line.removePrefix("Bridge ").removePrefix("bridge ")
                } else {
                    line
                }
                "Bridge=${TorControlWire.quotedString(v)}"
            }
            transport.command("SETCONF UseBridges=1 $bridges")
        }
        Unit
    }

    /**
     * Issues RESOLVE (control-spec §3.20). Answer arrives asynchronously via ADDRMAP;
     * [awaitResolveMapping] / client event wait should observe it. This only sends the command.
     */
    fun sendResolve(hostname: String): Result<Unit> = runCatching {
        val host = TorControlWire.requireHostname(hostname)
        transport.command("RESOLVE $host")
        Unit
    }

    /**
     * Fallback poll of address-mappings/cache after RESOLVE (prefer ADDRMAP events).
     */
    fun pollResolveMapping(hostname: String): String? {
        val host = TorControlWire.requireHostname(hostname)
        val maps = runCatching { getInfo("address-mappings/cache") }.getOrDefault("")
        maps.lineSequence().forEach { line ->
            val parts = line.trim().split(' ')
            if (parts.size >= 2 && parts[0].equals(host, ignoreCase = true)) {
                val mapped = parts[1]
                if (mapped.isNotBlank() && mapped != "<error>") return mapped
            }
        }
        return null
    }

    /**
     * Tor-side DNS: RESOLVE + poll address-mappings/cache (ADDRMAP is preferred at client).
     */
    fun resolve(hostname: String, timeoutMs: Long = 15_000): Result<String> = runCatching {
        val host = TorControlWire.requireHostname(hostname)
        sendResolve(host).getOrThrow()
        val deadline = System.currentTimeMillis() + timeoutMs
        var sleepMs = 50L
        while (System.currentTimeMillis() < deadline) {
            pollResolveMapping(host)?.let { return@runCatching it }
            Thread.sleep(sleepMs)
            sleepMs = (sleepMs * 2).coerceAtMost(400L)
        }
        throw IOException("RESOLVE timeout for $host")
    }

    fun extendNewCircuit(): Result<String> = runCatching {
        val lines = transport.command("EXTENDCIRCUIT 0")
        lines.firstOrNull { it.startsWith("250 ") }?.substringAfter("EXTENDED ")?.trim().orEmpty()
    }

    fun closeCircuit(id: String, ifUnused: Boolean = true): Result<Unit> = runCatching {
        val circId = TorControlWire.requireCircuitOrStreamId(id, "CircuitID")
        val flags = if (ifUnused) " IfUnused" else ""
        transport.command("CLOSECIRCUIT $circId$flags")
        Unit
    }

    fun closeStream(
        id: String,
        reason: String = TorControlCatalog.StreamEndReason.DONE,
    ): Result<Unit> = runCatching {
        val streamId = TorControlWire.requireCircuitOrStreamId(id, "StreamID")
        // control-spec: Reason is a decimal RELAY_END code — not a name like "DONE".
        val code = reason.trim()
        if (code.isEmpty() || !code.all { it.isDigit() }) {
            throw IOException("CLOSESTREAM reason must be decimal RELAY_END code, got: $reason")
        }
        transport.command("CLOSESTREAM $streamId $code")
        Unit
    }

    fun listCircuits(): List<TorCircuitInfo> =
        TorStatusListParser.parseCircuitStatus(getInfo("circuit-status"))

    fun listStreams(): List<TorStreamInfo> =
        TorStatusListParser.parseStreamStatus(getInfo("stream-status"))

    fun closeBuiltCircuits(): Result<Int> = runCatching {
        var closed = 0
        listCircuits().forEach { circ ->
            if (circ.status == "BUILT" || circ.status == "EXTENDED" || circ.status == "GUARD_WAIT") {
                runCatching { closeCircuit(circ.id, ifUnused = false).getOrThrow() }
                closed++
            }
        }
        refreshInfo()
        closed
    }

    fun getConf(vararg keys: String): Map<String, String> {
        val lines = transport.command("GETCONF ${keys.joinToString(" ")}")
        val out = linkedMapOf<String, String>()
        lines.forEach { line ->
            if (!line.startsWith("250")) return@forEach
            val body = line.removePrefix("250-").removePrefix("250 ")
            val eq = body.indexOf('=')
            if (eq > 0) out[body.substring(0, eq)] = body.substring(eq + 1).trim('"')
        }
        return out
    }

    fun getInfo(key: String): String {
        val lines = transport.command("GETINFO $key")
        return TorControlReplyParser.multilineValue(lines, key)
    }

    /** Single round-trip for multiple single-line GETINFO keys. */
    fun getInfoMany(vararg keys: String): Map<String, String> {
        if (keys.isEmpty()) return emptyMap()
        val lines = transport.command("GETINFO ${keys.joinToString(" ")}")
        val out = LinkedHashMap<String, String>(keys.size)
        for (key in keys) {
            out[key] = TorControlReplyParser.multilineValue(lines, key)
        }
        return out
    }

    fun rawCommand(cmd: String): Result<List<String>> = runCatching { transport.command(cmd) }

    fun setNodePrefs(entry: String, exit: String, exclude: String): Result<Unit> = runCatching {
        fun conf(key: String, value: String) {
            val v = value.trim()
            if (v.isEmpty()) {
                transport.command("RESETCONF $key")
            } else if (v.any { it == '\r' || it == '\n' }) {
                throw IOException("invalid SETCONF $key value (CRLF)")
            } else {
                transport.command("SETCONF $key=${TorControlWire.quotedString(v)}")
            }
        }
        conf("EntryNodes", entry)
        conf("ExitNodes", exit)
        conf("ExcludeNodes", exclude)
    }

    companion object {
        /** Tor enforces ~10s between NEWNYM; pad slightly for clock skew. */
        const val NEWNYM_MIN_INTERVAL_MS = 10_500L
    }
}
