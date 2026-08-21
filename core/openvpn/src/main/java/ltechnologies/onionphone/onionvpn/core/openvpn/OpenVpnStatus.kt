package ltechnologies.onionphone.onionvpn.core.openvpn

/**
 * Runtime state of the optional OpenVPN-over-Tor client.
 */
enum class OpenVpnPhase {
    Idle,
    Starting,
    Up,
    Stopping,
    Error,
}

data class OpenVpnStatus(
    val phase: OpenVpnPhase = OpenVpnPhase.Idle,
    val detail: String = "",
)
