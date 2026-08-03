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
        identityRefreshing: Boolean = false,
        /**
         * Onionmasq plane: single TorClient readiness from [OnionVpnService.onionmasqReady].
         * arti-mobile [TorControlStatus] stays cold — without this, NEWNYM stays disabled.
         */
        onionmasqReady: Boolean = false,
        newNymCooldownUntilMs: Long = 0L,
    ): TunnelSnapshot {
        val caps = torEngine.capabilities
        val proxiesLive = phase == TunnelPhase.Connected ||
            phase == TunnelPhase.Validating ||
            phase == TunnelPhase.StartingVpn
        // On onionmasq, "torRunning" in the snapshot means the data-plane TorClient is live,
        // not arti-mobile ProcessManager.
        val engineLive = torRunning || onionmasqReady
        val ports = runtimePorts?.takeIf { proxiesLive && engineLive }
        val built = if (liveBuiltCircuits >= 0) liveBuiltCircuits else torStatus.builtCircuits
        val streams = if (liveStreamCount >= 0) liveStreamCount else torStatus.streamCount
        val runtimeReady = when {
            onionmasqReady -> true
            else -> torRunning && (
                torStatus.bootstrapProgress >= 100 ||
                    torStatus.circuitEstablished ||
                    torStatus.connected
                )
        }
        return TunnelSnapshot(
            phase = phase,
            killSwitchEnabled = true,
            torRunning = engineLive,
            dnsCryptRunning = dnsCryptRunning,
            vpnEstablished = vpnEstablished,
            validations = validations,
            lastError = lastError,
            throughputText = if (phase == TunnelPhase.Connected) throughputText else "",
            torEngine = torEngine,
            torBootstrapProgress = if (onionmasqReady && torStatus.bootstrapProgress <= 0) {
                100
            } else {
                torStatus.bootstrapProgress
            },
            torBootstrapSummary = torStatus.bootstrapSummary.ifBlank {
                if (onionmasqReady) "onionmasq ready_for_traffic" else ""
            },
            torControlConnected = caps.classicControlPlane && torStatus.connected,
            torRuntimeReady = runtimeReady,
            torControlPlaneAvailable = caps.classicControlPlane && torStatus.connected,
            torBuiltCircuits = if (caps.circuitInspection) built else 0,
            torCircuitEstablished = torStatus.circuitEstablished ||
                (caps.circuitInspection && built > 0) ||
                (torEngine == TorEngine.ARTI && runtimeReady) ||
                (torEngine == TorEngine.KOTLIN_TOR && runtimeReady) ||
                onionmasqReady,
            torVersion = torStatus.torVersion.ifBlank {
                when {
                    onionmasqReady -> "onionmasq"
                    torEngine == TorEngine.ARTI -> "arti-mobile"
                    torEngine == TorEngine.KOTLIN_TOR -> "kotlin-tor"
                    else -> ""
                }
            },
            torStreamCount = if (caps.circuitInspection) streams else 0,
            torNetworkLive = torStatus.networkLive ||
                (torEngine == TorEngine.ARTI && runtimeReady) ||
                (torEngine == TorEngine.KOTLIN_TOR && runtimeReady) ||
                onionmasqReady,
            torDormant = if (caps.dormantSignals) torStatus.dormant else false,
            torEntryGuards = if (caps.classicControlPlane) torStatus.entryGuardsSummary else "",
            torLastCircEvent = if (caps.circuitInspection) torStatus.lastCircEvent else "",
            pacUrl = if (ports != null) TunnelEndpoints.pacUrl() else "",
            socksProxy = ports?.let { TunnelEndpoints.pacSocksBridge() }.orEmpty(),
            httpProxy = "", // HTTPTunnelPort disabled — use PAC bridge (DNSCrypt), not Tor exit DNS
            identityRefreshing = identityRefreshing,
            newNymCooldownUntilMs = newNymCooldownUntilMs,
        )
    }

    /** [bytesPerSec] → Mbit/s (bits), same unit family as Speedtest / ISP. */
    fun formatRate(bytesPerSec: Long): String {
        val bits = bytesPerSec * 8.0
        return when {
            bits >= 1_000_000 -> "%.1f Mbit/s".format(bits / 1_000_000.0)
            bits >= 1_000 -> "%.0f Kbit/s".format(bits / 1_000.0)
            else -> "%.0f bit/s".format(bits)
        }
    }
}
