package ltechnologies.onionphone.onionvpn.core.tor

/**
 * Live Tor control-plane state (control-spec events + GETINFO).
 */
data class TorControlStatus(
    val connected: Boolean = false,
    val bootstrapProgress: Int = 0,
    val bootstrapTag: String = "",
    val bootstrapSummary: String = "",
    val circuitEstablished: Boolean = false,
    val enoughDirInfo: Boolean = false,
    val dormant: Boolean = false,
    /** Built (open) circuits from last CIRC/GETINFO snapshot. */
    val builtCircuits: Int = 0,
    val failedCircuitsRecent: Int = 0,
    val lastCircEvent: String = "",
    val readBytes: Long = 0L,
    val writeBytes: Long = 0L,
    val lastError: String? = null,
)

sealed interface TorControlEvent {
    data class Bootstrap(
        val progress: Int,
        val tag: String,
        val summary: String,
        val warning: String? = null,
        val reason: String? = null,
    ) : TorControlEvent

    data class Circuit(
        val id: String,
        val status: String,
        val path: String,
        val reason: String? = null,
    ) : TorControlEvent

    data class Bandwidth(val read: Long, val written: Long) : TorControlEvent

    data class Notice(val line: String) : TorControlEvent

    data class Guard(val line: String) : TorControlEvent
}
