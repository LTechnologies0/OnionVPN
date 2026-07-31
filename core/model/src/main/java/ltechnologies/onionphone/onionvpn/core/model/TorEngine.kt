package ltechnologies.onionphone.onionvpn.core.model

/**
 * Which Tor client implementation drives the tunnel.
 *
 * - [LITTLE_T]: classic C Tor (`libtor.so` + torrc + ControlSocket).
 * - [ARTI]: Rust Arti via Guardian Project / Tor Project `arti-mobile`
 *   (in-process SOCKS + DNS proxy; no classic control port).
 */
enum class TorEngine {
    LITTLE_T,
    ARTI,
    ;

    val displayName: String
        get() = when (this) {
            LITTLE_T -> "C Tor (libtor)"
            ARTI -> "Arti (Rust)"
        }

    companion object {
        fun fromPreference(raw: String?): TorEngine =
            entries.firstOrNull { it.name.equals(raw, ignoreCase = true) } ?: LITTLE_T
    }
}
