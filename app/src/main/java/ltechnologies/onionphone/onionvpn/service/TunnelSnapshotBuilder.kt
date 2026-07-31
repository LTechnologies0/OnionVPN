package ltechnologies.onionphone.onionvpn.service

import ltechnologies.onionphone.onionvpn.core.model.TorEngine
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelPhase
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.model.TunnelSnapshot
import ltechnologies.onionphone.onionvpn.core.model.ValidationCheck
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlStatus

/**
 * Pure builder: merges prefs + Tor control status + phase into [TunnelSnapshot].
 */
internal object TunnelSnapshotBuilder {
    fun build(
        phase: TunnelPhase,
        preferences: TunnelPreferences,
        torStatus: TorControlStatus,
        throughputText: String,
        validations: List<ValidationCheck>,
        torRunning: Boolean,
        dnsCryptRunning: Boolean,
        vpnEstablished: Boolean,
        lastError: String?,
        runtimePorts: TunnelRuntimePorts? = null,
        /** Prefer live ControlPort circuit list (Status used to show 0 while Circuits had many). */
        liveBuiltCircuits: Int = -1,
        liveStreamCount: Int = -1,
        torEngine: TorEngine = preferences.torEngine,
    ): TunnelSnapshot {
        val caps = torEngine.capabilities
        val proxiesLive = phase == TunnelPhase.Connected ||
            phase == TunnelPhase.Validating ||
            phase == TunnelPhase.StartingVpn
        val ports = runtimePorts?.takeIf { proxiesLive && torRunning }
        val built = if (liveBuiltCircuits >= 0) liveBuiltCircuits else torStatus.builtCircuits
        val streams = if (liveStreamCount >= 0) liveStreamCount else torStatus.streamCount
        val runtimeReady = torRunning && (
            torStatus.bootstrapProgress >= 100 ||
                torStatus.circuitEstablished ||
                torStatus.connected
            )
        return TunnelSnapshot(
            phase = phase,
            killSwitchEnabled = true,
            torRunning = torRunning,
            dnsCryptRunning = dnsCryptRunning,
            vpnEstablished = vpnEstablished,
            validations = validations,
            lastError = lastError,
            throughputText = if (phase == TunnelPhase.Connected) throughputText else "",
            torEngine = torEngine,
            torBootstrapProgress = torStatus.bootstrapProgress,
            torBootstrapSummary = torStatus.bootstrapSummary,
            torControlConnected = caps.classicControlPlane && torStatus.connected,
            torRuntimeReady = runtimeReady,
            torControlPlaneAvailable = caps.classicControlPlane && torStatus.connected,
            torBuiltCircuits = if (caps.circuitInspection) built else 0,
            torCircuitEstablished = torStatus.circuitEstablished ||
                (caps.circuitInspection && built > 0) ||
                (torEngine == TorEngine.ARTI && runtimeReady),
            torVersion = torStatus.torVersion.ifBlank {
                if (torEngine == TorEngine.ARTI) "arti-mobile" else ""
            },
            torStreamCount = if (caps.circuitInspection) streams else 0,
            torNetworkLive = torStatus.networkLive || (torEngine == TorEngine.ARTI && runtimeReady),
            torDormant = if (caps.dormantSignals) torStatus.dormant else false,
            torEntryGuards = if (caps.classicControlPlane) torStatus.entryGuardsSummary else "",
            torLastCircEvent = if (caps.circuitInspection) torStatus.lastCircEvent else "",
            pacUrl = if (ports != null) TunnelEndpoints.pacUrl() else "",
            socksProxy = ports?.let { TunnelEndpoints.pacSocksBridge() }.orEmpty(),
            httpProxy = "", // HTTPTunnelPort disabled — use PAC bridge (DNSCrypt), not Tor exit DNS
        )
    }

    fun formatRate(bytesPerSec: Long): String = when {
        bytesPerSec >= 1_000_000 -> "%.1f MB/s".format(bytesPerSec / 1_000_000.0)
        bytesPerSec >= 1_000 -> "%.0f KB/s".format(bytesPerSec / 1_000.0)
        else -> "$bytesPerSec B/s"
    }
}
