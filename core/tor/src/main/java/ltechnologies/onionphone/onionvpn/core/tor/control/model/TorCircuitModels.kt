package ltechnologies.onionphone.onionvpn.core.tor.control.model

/**
 * Parsed GETINFO circuit-status / stream-status rows for UI and lifecycle.
 */

data class TorCircuitInfo(
    val id: String,
    val status: String,
    val path: String = "",
    val purpose: String = "",
    val buildFlags: String = "",
    val socksUsername: String? = null,
    val socksPassword: String? = null,
    val timeCreated: String? = null,
    val hsState: String? = null,
    val reason: String? = null,
)

data class TorStreamInfo(
    val id: String,
    val status: String,
    val circuitId: String,
    val target: String,
    val sourceAddr: String? = null,
    val purpose: String? = null,
    val socksUsername: String? = null,
    val socksPassword: String? = null,
    val clientProtocol: String? = null,
    val reason: String? = null,
)
