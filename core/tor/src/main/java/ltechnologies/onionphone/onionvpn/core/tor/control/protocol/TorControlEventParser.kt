package ltechnologies.onionphone.onionvpn.core.tor.control.protocol

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
            val parts = payload.split(' ')
            if (parts.size >= 4) {
                Result(TorControlEvent.AddrMap(parts[1], parts[2], parts[3]))
            } else {
                Result()
            }
        }
        payload.startsWith("BW ") -> {
            val parts = payload.split(' ')
            if (parts.size >= 3) {
                Result(
                    TorControlEvent.Bandwidth(
                        parts[1].toLongOrNull() ?: 0L,
                        parts[2].toLongOrNull() ?: 0L,
                    ),
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
        val parts = payload.split(' ')
        if (parts.size < 3) return Result()
        val id = parts[1]
        val st = parts[2]
        val reason = parts.firstOrNull { it.startsWith("REASON=") }?.substringAfter('=')
        val path = parts.getOrNull(3)?.takeIf { !it.contains('=') }.orEmpty()
        val event = TorControlEvent.Circuit(id, st, path, reason)
        return Result(
            event = event,
            statusPatch = { status ->
                if (st == "FAILED" || st == "CLOSED") {
                    status.copy(
                        failedCircuitsRecent = status.failedCircuitsRecent + 1,
                        lastCircEvent = "$st $id ${reason.orEmpty()}".trim(),
                    )
                } else {
                    status.copy(lastCircEvent = "$st $id")
                }
            },
        )
    }

    private fun parseStream(payload: String): Result {
        val parts = payload.split(' ')
        if (parts.size < 5) return Result()
        val id = parts[1]
        val st = parts[2]
        val circ = parts[3]
        val target = parts[4]
        val reason = parts.firstOrNull { it.startsWith("REASON=") }?.substringAfter('=')
        val event = TorControlEvent.Stream(id, st, circ, target, reason)
        return Result(
            event = event,
            statusPatch = { status ->
                if (st == "FAILED" || st == "CLOSED") {
                    status.copy(
                        failedStreamsRecent = status.failedStreamsRecent + 1,
                        lastStreamEvent = "$st $target",
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
                    status.copy(orConnCount = status.orConnCount + 1)
                } else {
                    status
                }
            },
        )
    }
}
