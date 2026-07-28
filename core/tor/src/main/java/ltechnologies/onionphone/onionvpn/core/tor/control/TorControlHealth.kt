package ltechnologies.onionphone.onionvpn.core.tor.control

import ltechnologies.onionphone.onionvpn.core.model.ValidationCheck
import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlStatus

/**
 * Maps [TorControlStatus] into a tunnel [ValidationCheck] row.
 *
 * Imported by the app tunnel service after SOCKS/DNS path validation.
 * Soft-fails (tripsKillSwitch=false) while bootstrapping; hard-fails only when
 * stuck with no progress and no circuits.
 */
object TorControlHealth {
    /**
     * @param status current control snapshot
     * @param requireConnected when true, disconnected → Fail (Connected phase)
     */
    fun validate(status: TorControlStatus, requireConnected: Boolean = true): ValidationCheck {
        if (requireConnected && !status.connected) {
            return ValidationCheck(
                id = "tor.control.connected",
                label = "Tor ControlPort",
                status = ValidationStatus.Fail,
                detail = "ControlSocket not connected",
                tripsKillSwitch = true,
            )
        }
        if (!status.connected) {
            return ValidationCheck(
                id = "tor.control.connected",
                label = "Tor ControlPort",
                status = ValidationStatus.Skipped,
                detail = "Control not required in this phase",
                tripsKillSwitch = false,
            )
        }
        val bootOk = status.bootstrapProgress >= 100 || status.circuitEstablished
        val ok = bootOk && status.enoughDirInfo
        val detail = buildString {
            append("v=${status.torVersion.ifBlank { "?" }} ")
            append("boot=${status.bootstrapProgress}% ")
            append("circ=${status.builtCircuits} ")
            append("streams=${status.streamCount} ")
            append("live=${status.networkLive} ")
            append("dormant=${status.dormant} ")
            if (status.entryGuardsSummary.isNotBlank()) {
                append("guards=[${status.entryGuardsSummary}] ")
            }
            if (status.lastCircEvent.isNotBlank()) append("lastCirc=${status.lastCircEvent} ")
            if (status.lastError != null) append("err=${status.lastError}")
        }.trim()
        return ValidationCheck(
            id = "tor.control.health",
            label = "Tor control health",
            status = if (ok) ValidationStatus.Pass else ValidationStatus.Fail,
            detail = detail,
            tripsKillSwitch = !bootOk && status.bootstrapProgress == 0,
        )
    }
}
