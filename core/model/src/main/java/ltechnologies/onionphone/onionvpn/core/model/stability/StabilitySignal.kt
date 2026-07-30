package ltechnologies.onionphone.onionvpn.core.model.stability

/**
 * Severity and recovery hints for Tor / DNSCrypt / OS wire codes.
 * Used to keep the tunnel stable: ignore noise, soft-retry path issues,
 * hard-recover when the underlay is dead, never escalate DONE/FINISHED.
 */
enum class StabilitySeverity {
    /** Expected / benign (DONE, FINISHED, idle close). */
    IGNORE,
    /** Informational — log at DEBUG/INFO only. */
    INFO,
    /** Degraded path — soft recovery (ACTIVE / CLEARDNSCACHE). */
    WARN,
    /** User-visible failure — may trip kill-switch if persistent. */
    ERROR,
    /** Process / control plane unusable — stop Tor or Blocking TUN. */
    CRITICAL,
}

enum class StabilityAction {
    NONE,
    /** SIGNAL ACTIVE + CLEARDNSCACHE (network flipped). */
    SOFT_RECOVER,
    /** DisableNetwork bounce / DROPTIMEOUTS (prolonged NOROUTE). */
    HARD_RECOVER,
    /** Prefer kill-switch Blocking TUN while keeping Tor when possible. */
    PREFER_BLOCKING,
    /** Tear down Tor process (binary/control dead). */
    STOP_TOR,
}

data class StabilitySignal(
    val code: String,
    val severity: StabilitySeverity,
    val action: StabilityAction = StabilityAction.NONE,
    val detail: String = "",
) {
    val isError: Boolean
        get() = severity == StabilitySeverity.ERROR || severity == StabilitySeverity.CRITICAL

    val isWarnOrWorse: Boolean
        get() = severity >= StabilitySeverity.WARN
}
