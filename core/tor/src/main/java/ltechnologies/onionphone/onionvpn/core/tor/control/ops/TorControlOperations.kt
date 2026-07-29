package ltechnologies.onionphone.onionvpn.core.tor.control.ops

import java.io.IOException
import ltechnologies.onionphone.onionvpn.core.tor.control.catalog.TorControlCatalog
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorCircuitInfo
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorStreamInfo
import ltechnologies.onionphone.onionvpn.core.tor.control.protocol.TorControlReplyParser
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

    fun newNym(): Result<Unit> = signal(TorControlCatalog.Signal.NEWNYM).also {
        runCatching { signal(TorControlCatalog.Signal.CLEARDNSCACHE) }
    }

    /**
     * Rate-limited NEWNYM (control-spec: Tor rejects rapid NEWNYM ~10s with 551).
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
                "Bridge=\"$v\""
            }
            transport.command("SETCONF UseBridges=1 $bridges")
        }
        Unit
    }

    /**
     * Tor-side DNS (async ADDRMAP). Polls address-mappings/all briefly until hit or timeout.
     */
    fun resolve(hostname: String, timeoutMs: Long = 15_000): Result<String> = runCatching {
        transport.command("RESOLVE $hostname")
        val deadline = System.currentTimeMillis() + timeoutMs
        var sleepMs = 50L
        while (System.currentTimeMillis() < deadline) {
            val maps = getInfo("address-mappings/all")
            maps.lineSequence().forEach { line ->
                val parts = line.trim().split(' ')
                if (parts.size >= 2 && parts[0].equals(hostname, ignoreCase = true)) {
                    return@runCatching parts[1]
                }
            }
            Thread.sleep(sleepMs)
            sleepMs = (sleepMs * 2).coerceAtMost(400L)
        }
        throw IOException("RESOLVE timeout for $hostname")
    }

    fun extendNewCircuit(): Result<String> = runCatching {
        val lines = transport.command("EXTENDCIRCUIT 0")
        lines.firstOrNull { it.startsWith("250 ") }?.substringAfter("EXTENDED ")?.trim().orEmpty()
    }

    fun closeCircuit(id: String, ifUnused: Boolean = true): Result<Unit> = runCatching {
        val flags = if (ifUnused) " IfUnused" else ""
        transport.command("CLOSECIRCUIT $id$flags")
        Unit
    }

    fun closeStream(id: String, reason: String = "DONE"): Result<Unit> = runCatching {
        transport.command("CLOSESTREAM $id $reason")
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
                runCatching { transport.command("CLOSECIRCUIT ${circ.id}") }
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
            } else {
                transport.command("SETCONF $key=\"$v\"")
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
