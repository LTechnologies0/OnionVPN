package ltechnologies.onionphone.onionvpn.core.model.stability

/**
 * Tor control-spec / tor-spec wire reason catalogs used for stability decisions.
 *
 * @see <a href="https://spec.torproject.org/tor-spec/closing-streams.html">RELAY_END reasons</a>
 * @see <a href="https://spec.torproject.org/control-spec/replies.html">CIRC/STREAM/ORCONN REASON=</a>
 * @see <a href="https://spec.torproject.org/socks-extensions.html">SOCKS extended errors</a>
 */
object TorStabilityCodes {

    /**
     * RELAY_END reason byte (CLOSESTREAM decimal) ↔ control STREAM REASON name.
     */
    enum class StreamEnd(
        val code: Int,
        val wire: String,
        val severity: StabilitySeverity,
        val action: StabilityAction = StabilityAction.NONE,
    ) {
        MISC(1, "MISC", StabilitySeverity.WARN),
        RESOLVEFAILED(2, "RESOLVEFAILED", StabilitySeverity.WARN),
        CONNECTREFUSED(3, "CONNECTREFUSED", StabilitySeverity.INFO),
        EXITPOLICY(4, "EXITPOLICY", StabilitySeverity.INFO),
        DESTROY(5, "DESTROY", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        DONE(6, "DONE", StabilitySeverity.IGNORE),
        // Single stream TIMEOUT is normal under exit load — do not DROPTIMEOUTS.
        TIMEOUT(7, "TIMEOUT", StabilitySeverity.WARN),
        NOROUTE(8, "NOROUTE", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        HIBERNATING(9, "HIBERNATING", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        INTERNAL(10, "INTERNAL", StabilitySeverity.ERROR),
        RESOURCELIMIT(11, "RESOURCELIMIT", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        CONNRESET(12, "CONNRESET", StabilitySeverity.WARN),
        TORPROTOCOL(13, "TORPROTOCOL", StabilitySeverity.ERROR),
        NOTDIRECTORY(14, "NOTDIRECTORY", StabilitySeverity.INFO),
        // control-spec STREAM-only names (no RELAY_END byte)
        END(-1, "END", StabilitySeverity.INFO),
        PRIVATE_ADDR(-2, "PRIVATE_ADDR", StabilitySeverity.INFO),
        ;

        fun signal(): StabilitySignal = StabilitySignal(wire, severity, action)

        companion object {
            fun fromCode(code: Int): StreamEnd? = entries.firstOrNull { it.code == code && it.code > 0 }
            fun fromWire(name: String): StreamEnd? =
                entries.firstOrNull { it.wire.equals(name.trim(), ignoreCase = true) }

            fun signalFor(nameOrCode: String?): StabilitySignal {
                if (nameOrCode.isNullOrBlank()) {
                    return StabilitySignal("UNKNOWN", StabilitySeverity.INFO)
                }
                val trimmed = nameOrCode.trim()
                fromWire(trimmed)?.let { return it.signal() }
                trimmed.toIntOrNull()?.let { n -> fromCode(n)?.let { return it.signal() } }
                return StabilitySignal(trimmed.uppercase(), StabilitySeverity.WARN)
            }
        }
    }

    /** CIRC FAILED/CLOSED REASON= (control-spec §4.1.1). */
    enum class CircReason(
        val wire: String,
        val severity: StabilitySeverity,
        val action: StabilityAction = StabilityAction.NONE,
    ) {
        NONE("NONE", StabilitySeverity.IGNORE),
        TORPROTOCOL("TORPROTOCOL", StabilitySeverity.ERROR),
        INTERNAL("INTERNAL", StabilitySeverity.ERROR),
        REQUESTED("REQUESTED", StabilitySeverity.IGNORE),
        HIBERNATING("HIBERNATING", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        RESOURCELIMIT("RESOURCELIMIT", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        CONNECTFAILED("CONNECTFAILED", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        OR_IDENTITY("OR_IDENTITY", StabilitySeverity.WARN),
        OR_CONN_CLOSED("OR_CONN_CLOSED", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        // Circuit build TIMEOUT is expected while learning CBT — soft-recover floods apps.
        TIMEOUT("TIMEOUT", StabilitySeverity.WARN),
        FINISHED("FINISHED", StabilitySeverity.IGNORE),
        DESTROYED("DESTROYED", StabilitySeverity.WARN),
        NOPATH("NOPATH", StabilitySeverity.ERROR, StabilityAction.SOFT_RECOVER),
        NOSUCHSERVICE("NOSUCHSERVICE", StabilitySeverity.INFO),
        MEASUREMENT_EXPIRED("MEASUREMENT_EXPIRED", StabilitySeverity.IGNORE),
        IP_NOW_REDUNDANT("IP_NOW_REDUNDANT", StabilitySeverity.IGNORE),
        ;

        fun signal(): StabilitySignal = StabilitySignal(wire, severity, action)

        companion object {
            fun fromWire(name: String?): CircReason? =
                name?.let { n -> entries.firstOrNull { it.wire.equals(n.trim(), ignoreCase = true) } }

            fun signalFor(name: String?): StabilitySignal =
                fromWire(name)?.signal()
                    ?: StabilitySignal(name?.uppercase() ?: "UNKNOWN", StabilitySeverity.WARN)
        }
    }

    /** ORCONN REASON= (control-spec §4.1.3). */
    enum class OrConnReason(
        val wire: String,
        val severity: StabilitySeverity,
        val action: StabilityAction = StabilityAction.NONE,
    ) {
        MISC("MISC", StabilitySeverity.WARN),
        DONE("DONE", StabilitySeverity.IGNORE),
        CONNECTREFUSED("CONNECTREFUSED", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        IDENTITY("IDENTITY", StabilitySeverity.WARN),
        CONNECTRESET("CONNECTRESET", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        // One ORCONN TIMEOUT while guards rotate is noise; NOROUTE still hard-recovers.
        TIMEOUT("TIMEOUT", StabilitySeverity.WARN),
        NOROUTE("NOROUTE", StabilitySeverity.WARN, StabilityAction.HARD_RECOVER),
        IOERROR("IOERROR", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        RESOURCELIMIT("RESOURCELIMIT", StabilitySeverity.WARN),
        TLS_ERROR("TLS_ERROR", StabilitySeverity.ERROR, StabilityAction.SOFT_RECOVER),
        PT_MISSING("PT_MISSING", StabilitySeverity.CRITICAL, StabilityAction.PREFER_BLOCKING),
        ;

        fun signal(): StabilitySignal = StabilitySignal(wire, severity, action)

        companion object {
            fun fromWire(name: String?): OrConnReason? =
                name?.let { n -> entries.firstOrNull { it.wire.equals(n.trim(), ignoreCase = true) } }

            fun signalFor(name: String?): StabilitySignal =
                fromWire(name)?.signal()
                    ?: StabilitySignal(name?.uppercase() ?: "UNKNOWN", StabilitySeverity.WARN)
        }
    }

    /**
     * SOCKS5 reply status (RFC 1928) + Tor onion extended errors (socks-extensions).
     */
    enum class SocksReply(
        val code: Int,
        val label: String,
        val severity: StabilitySeverity,
        val action: StabilityAction = StabilityAction.NONE,
    ) {
        SUCCEEDED(0x00, "succeeded", StabilitySeverity.IGNORE),
        GENERAL_FAILURE(0x01, "general failure", StabilitySeverity.ERROR),
        NOT_ALLOWED(0x02, "not allowed", StabilitySeverity.INFO),
        NETWORK_UNREACHABLE(0x03, "network unreachable", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        HOST_UNREACHABLE(0x04, "host unreachable", StabilitySeverity.WARN),
        CONNECTION_REFUSED(0x05, "connection refused", StabilitySeverity.INFO),
        TTL_EXPIRED(0x06, "TTL expired", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        COMMAND_NOT_SUPPORTED(0x07, "command not supported", StabilitySeverity.ERROR),
        ADDRESS_TYPE_NOT_SUPPORTED(0x08, "address type not supported", StabilitySeverity.ERROR),
        // Tor onion extensions
        HS_DESC_NOT_FOUND(0xF0, "onion descriptor not found", StabilitySeverity.INFO),
        HS_DESC_INVALID(0xF1, "onion descriptor invalid", StabilitySeverity.WARN),
        HS_INTRO_FAILED(0xF2, "onion introduction failed", StabilitySeverity.WARN),
        HS_REND_FAILED(0xF3, "onion rendezvous failed", StabilitySeverity.WARN),
        HS_MISSING_CLIENT_AUTH(0xF4, "onion missing client auth", StabilitySeverity.INFO),
        HS_WRONG_CLIENT_AUTH(0xF5, "onion wrong client auth", StabilitySeverity.INFO),
        HS_INVALID_ADDRESS(0xF6, "onion invalid address", StabilitySeverity.INFO),
        HS_INTRO_TIMEOUT(0xF7, "onion introduction timeout", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        ;

        fun signal(): StabilitySignal =
            StabilitySignal("SOCKS_$code", severity, action, label)

        companion object {
            fun fromCode(code: Int): SocksReply? = entries.firstOrNull { it.code == code }

            fun signalFor(code: Int): StabilitySignal =
                fromCode(code)?.signal()
                    ?: StabilitySignal("SOCKS_$code", StabilitySeverity.ERROR, detail = "unknown SOCKS status")
        }
    }

    /** Control reply status families (message-format / replies). */
    enum class ControlStatus(
        val codePrefix: Char,
        val severity: StabilitySeverity,
        val action: StabilityAction = StabilityAction.NONE,
    ) {
        OK('2', StabilitySeverity.IGNORE),
        TEMP_NEGATIVE('4', StabilitySeverity.WARN),
        ERROR('5', StabilitySeverity.ERROR),
        ;

        companion object {
            fun signalForLine(line: String): StabilitySignal? {
                if (line.length < 3 || !line[0].isDigit()) return null
                return when (line[0]) {
                    '2' -> StabilitySignal(line.take(3), StabilitySeverity.IGNORE)
                    '4' -> StabilitySignal(line.take(3), StabilitySeverity.WARN)
                    '5' -> {
                        val code = line.take(3)
                        val action = when (code) {
                            "551" -> StabilityAction.NONE // rate-limit / unavailable
                            "552" -> StabilityAction.NONE // unrecognized
                            "514" -> StabilityAction.STOP_TOR // authentication required mid-session
                            else -> StabilityAction.NONE
                        }
                        val sev = if (code == "514" || code.startsWith("5") && "authenticate" in line.lowercase()) {
                            StabilitySeverity.CRITICAL
                        } else {
                            StabilitySeverity.ERROR
                        }
                        StabilitySignal(code, sev, action, line.drop(4).take(120))
                    }
                    else -> null
                }
            }
        }
    }
}
