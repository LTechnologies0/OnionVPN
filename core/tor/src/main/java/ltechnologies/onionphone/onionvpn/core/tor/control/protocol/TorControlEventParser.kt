package ltechnologies.onionphone.onionvpn.core.tor.control.protocol

import ltechnologies.onionphone.onionvpn.core.model.stability.StabilityAction
import ltechnologies.onionphone.onionvpn.core.model.stability.StabilityClassifier
import ltechnologies.onionphone.onionvpn.core.model.stability.StabilitySignal
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlEvent
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlStatus

/**
 * Parses control-spec asynchronous event payloads (text after `650 ` / `650-`).
 *
 * Pure: returns an optional [TorControlEvent] and a status patch; no sockets.
 */
internal object TorControlEventParser {

    /**
     * Result of parsing one async payload.
     *
     * @property event typed event to emit (null if unrecognized / incomplete)
     * @property statusPatch pure function merging side-effects into [TorControlStatus]
     */
    data class Result(
        val event: TorControlEvent? = null,
        val statusPatch: (TorControlStatus) -> TorControlStatus = { it },
    )

    /** Alias for GETINFO status/bootstrap-phase bodies. */
    fun parseBootstrapPhase(raw: String): TorControlEvent.Bootstrap? = parseBootstrapEvent(raw)

    /**
     * Parses BOOTSTRAP PROGRESS/TAG/SUMMARY from STATUS_* or GETINFO bodies.
     */
    fun parseBootstrapEvent(payload: String): TorControlEvent.Bootstrap? {
        if (!payload.contains("BOOTSTRAP")) return null
        val progress = Regex("""PROGRESS=(\d+)""")
            .find(payload)?.groupValues?.get(1)?.toIntOrNull() ?: return null
        val tag = Regex("""TAG=(\S+)""").find(payload)?.groupValues?.get(1).orEmpty()
        val summary = Regex("""SUMMARY="([^"]*)"""").find(payload)?.groupValues?.get(1)
            ?: Regex("""SUMMARY=(\S+)""").find(payload)?.groupValues?.get(1).orEmpty()
        val warning = Regex("""WARNING="([^"]*)"""").find(payload)?.groupValues?.get(1)
        val reason = Regex("""REASON=(\S+)""").find(payload)?.groupValues?.get(1)
        return TorControlEvent.Bootstrap(progress, tag, summary, warning, reason)
    }

    /**
     * Dispatches a single 650 payload into event + status patch.
     */
    fun parseAsyncPayload(payload: String): Result = when {
        payload.contains("BOOTSTRAP") -> {
            val boot = parseBootstrapEvent(payload)
            if (boot == null) {
                Result()
            } else {
                Result(
                    event = boot,
                    statusPatch = {
                        it.copy(
                            bootstrapProgress = boot.progress,
                            bootstrapTag = boot.tag,
                            bootstrapSummary = boot.summary,
                        )
                    },
                )
            }
        }
        payload.startsWith("CIRC ") || payload.startsWith("CIRC_MINOR ") -> parseCirc(payload)
        payload.startsWith("STREAM ") -> parseStream(payload)
        payload.startsWith("ORCONN ") -> parseOrConn(payload)
        payload.startsWith("ADDRMAP ") -> {
            // Address SP NewAddress SP Expiry — Expiry may be quoted with spaces.
            val parts = TorStatusListParser.tokenize(payload.removePrefix("ADDRMAP "))
            if (parts.size >= 3) {
                Result(TorControlEvent.AddrMap(parts[0], parts[1], parts[2]))
            } else {
                Result()
            }
        }
        payload.startsWith("BW ") -> {
            val parts = payload.split(' ')
            if (parts.size >= 3) {
                val read = parts[1].toLongOrNull() ?: 0L
                val written = parts[2].toLongOrNull() ?: 0L
                Result(
                    event = TorControlEvent.Bandwidth(read, written),
                    statusPatch = { status ->
                        status.copy(
                            lastBwReadPerSec = read,
                            lastBwWritePerSec = written,
                        )
                    },
                )
            } else {
                Result()
            }
        }
        payload.startsWith("GUARD ") -> Result(TorControlEvent.Guard(payload))
        payload.startsWith("CONF_CHANGED") -> Result(TorControlEvent.ConfChanged(payload))
        payload.startsWith("SIGNAL ") ->
            Result(TorControlEvent.SignalReceived(payload.substringAfter("SIGNAL ").trim()))
        payload.startsWith("BUILDTIMEOUT_SET ") ->
            Result(TorControlEvent.BuildTimeoutSet(payload))
        payload.startsWith("TRANSPORT_LAUNCHED ") || payload.startsWith("PT_") ->
            Result(TorControlEvent.TransportLaunched(payload))
        payload.startsWith("NOTICE ") ||
            payload.startsWith("WARN ") ||
            payload.startsWith("ERR ") -> {
            val sev = payload.substringBefore(' ')
            Result(TorControlEvent.Notice(sev, payload))
        }
        else -> Result()
    }

    private fun parseCirc(payload: String): Result {
        val parts = TorStatusListParser.tokenize(payload.removePrefix("CIRC_MINOR ").removePrefix("CIRC "))
        if (parts.size < 2) return Result()
        val id = parts[0]
        val st = parts[1]
        val reason = TorStatusListParser.kv(parts, "REASON")
        val path = parts.getOrNull(2)?.takeIf { !it.contains('=') }.orEmpty()
        val event = TorControlEvent.Circuit(
            id = id,
            status = st,
            path = path,
            reason = reason,
            purpose = TorStatusListParser.kv(parts, "PURPOSE"),
            socksUsername = TorStatusListParser.kvQuoted(parts, "SOCKS_USERNAME"),
            socksPassword = TorStatusListParser.kvQuoted(parts, "SOCKS_PASSWORD"),
        )
        return Result(
            event = event,
            statusPatch = { status ->
                if (st == "FAILED" || st == "CLOSED") {
                    val signal = if (st == "FAILED") {
                        StabilityClassifier.forCircReason(reason)
                    } else {
                        null
                    }
                    status.copy(
                        failedCircuitsRecent = status.failedCircuitsRecent + 1,
                        lastCircEvent = "$st $id ${reason.orEmpty()}".trim(),
                        // Do not sticky-preserve SOFT/HARD — recovery edge-triggers on code.
                        lastStabilityAction = signal?.let { meaningfulAction(it) }.orEmpty()
                            .ifEmpty { status.lastStabilityAction },
                        lastStabilityCode = if (signal != null && signal.action != StabilityAction.NONE) {
                            signal.code
                        } else {
                            status.lastStabilityCode
                        },
                    )
                } else {
                    status.copy(lastCircEvent = "$st $id")
                }
            },
        )
    }

    private fun parseStream(payload: String): Result {
        val parts = TorStatusListParser.tokenize(payload.removePrefix("STREAM "))
        if (parts.size < 4) return Result()
        val id = parts[0]
        val st = parts[1]
        val circ = parts[2]
        val target = parts[3]
        val reason = TorStatusListParser.kv(parts, "REASON")
        val event = TorControlEvent.Stream(
            id = id,
            status = st,
            circuitId = circ,
            target = target,
            reason = reason,
            socksUsername = TorStatusListParser.kvQuoted(parts, "SOCKS_USERNAME"),
            socksPassword = TorStatusListParser.kvQuoted(parts, "SOCKS_PASSWORD"),
            clientProtocol = TorStatusListParser.kv(parts, "CLIENT_PROTOCOL"),
            purpose = TorStatusListParser.kv(parts, "PURPOSE"),
            sourceAddr = TorStatusListParser.kv(parts, "SOURCE_ADDR"),
        )
        return Result(
            event = event,
            statusPatch = { status ->
                if (st == "FAILED" || st == "CLOSED") {
                    val signal = if (st == "FAILED") {
                        StabilityClassifier.forStreamReason(reason)
                    } else {
                        null
                    }
                    status.copy(
                        failedStreamsRecent = status.failedStreamsRecent + 1,
                        lastStreamEvent = "$st $target",
                        lastStabilityAction = signal?.let { meaningfulAction(it) }
                            ?.ifEmpty { status.lastStabilityAction }
                            ?: status.lastStabilityAction,
                        lastStabilityCode = if (signal != null && signal.action != StabilityAction.NONE) {
                            signal.code
                        } else {
                            status.lastStabilityCode
                        },
                    )
                } else {
                    status.copy(lastStreamEvent = "$st $target")
                }
            },
        )
    }

    private fun parseOrConn(payload: String): Result {
        val parts = payload.split(' ')
        if (parts.size < 3) return Result()
        val target = parts[1]
        val st = parts[2]
        val reason = parts.firstOrNull { it.startsWith("REASON=") }?.substringAfter('=')
        return Result(
            event = TorControlEvent.OrConn(target, st, reason),
            statusPatch = { status ->
                if (st == "CONNECTED") {
                    status.copy(
                        orConnCount = status.orConnCount + 1,
                        lastStabilityAction = "",
                        lastStabilityCode = "",
                    )
                } else {
                    val signal = StabilityClassifier.forOrConnReason(reason)
                    status.copy(
                        lastStabilityAction = meaningfulAction(signal).ifEmpty { status.lastStabilityAction },
                        lastStabilityCode = if (signal.action != StabilityAction.NONE) {
                            signal.code
                        } else {
                            status.lastStabilityCode
                        },
                    )
                }
            },
        )
    }

    private fun meaningfulAction(signal: StabilitySignal): String =
        if (signal.action == StabilityAction.NONE) "" else signal.action.name
}
