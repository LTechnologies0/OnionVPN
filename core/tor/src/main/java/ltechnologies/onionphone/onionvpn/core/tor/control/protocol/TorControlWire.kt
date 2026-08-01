package ltechnologies.onionphone.onionvpn.core.tor.control.protocol

import java.io.IOException
import ltechnologies.onionphone.onionvpn.core.model.TorNetPolicy

/**
 * Control-spec wire helpers: QuotedString escaping and argument validation
 * so callers cannot inject CRLF / extra keywords into the command channel.
 *
 * @see <a href="https://spec.torproject.org/control-spec/message-format.html">message-format</a>
 */
internal object TorControlWire {
    private val ID_RE = Regex("^[A-Za-z0-9]{1,16}$")
    private val FINGERPRINT_RE = Regex("^[A-Fa-f0-9]{40}$")

    /**
     * Escapes a value for SETCONF `key="…"` (QuotedString: backslash and quote).
     */
    fun quotedString(value: String): String {
        val escaped = buildString(value.length + 8) {
            for (ch in value) {
                when (ch) {
                    '\\' -> append("\\\\")
                    '"' -> append("\\\"")
                    else -> append(ch)
                }
            }
        }
        return "\"$escaped\""
    }

    fun requireCircuitOrStreamId(id: String, label: String = "id"): String {
        val v = id.trim()
        if (!ID_RE.matches(v)) {
            throw IOException("invalid control $label: $id")
        }
        return v
    }

    fun requireFingerprintHex(fingerprint: String): String {
        val fp = fingerprint.removePrefix("$").uppercase()
        if (!FINGERPRINT_RE.matches(fp)) {
            throw IOException("invalid relay fingerprint")
        }
        return fp
    }

    /**
     * Hostnames for RESOLVE — torrified destination shape only (no CRLF injection).
     */
    fun requireHostname(hostname: String): String {
        val h = hostname.trim()
        if (!TorNetPolicy.isValidSocksDestination(h)) {
            throw IOException("invalid hostname for RESOLVE")
        }
        return h
    }
}
