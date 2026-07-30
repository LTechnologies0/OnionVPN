package ltechnologies.onionphone.onionvpn.core.model.stability

import android.system.OsConstants

/**
 * Android OS errno values that affect VPN / Tor / DNSCrypt process stability
 * (developer.android.com quality: avoid crash/ANR cascades from ignored I/O errors).
 */
object AndroidStabilityCodes {

    data class ErrnoSignal(
        val errno: Int,
        val name: String,
        val severity: StabilitySeverity,
        val action: StabilityAction,
    )

    private val MAP: Map<Int, ErrnoSignal> = listOf(
        ErrnoSignal(OsConstants.ENOENT, "ENOENT", StabilitySeverity.CRITICAL, StabilityAction.STOP_TOR),
        ErrnoSignal(OsConstants.EACCES, "EACCES", StabilitySeverity.CRITICAL, StabilityAction.STOP_TOR),
        ErrnoSignal(OsConstants.EPERM, "EPERM", StabilitySeverity.CRITICAL, StabilityAction.PREFER_BLOCKING),
        ErrnoSignal(OsConstants.EADDRINUSE, "EADDRINUSE", StabilitySeverity.ERROR, StabilityAction.PREFER_BLOCKING),
        ErrnoSignal(OsConstants.ECONNREFUSED, "ECONNREFUSED", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        ErrnoSignal(OsConstants.ETIMEDOUT, "ETIMEDOUT", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        ErrnoSignal(OsConstants.ENETUNREACH, "ENETUNREACH", StabilitySeverity.WARN, StabilityAction.HARD_RECOVER),
        ErrnoSignal(OsConstants.EHOSTUNREACH, "EHOSTUNREACH", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        ErrnoSignal(OsConstants.ECONNRESET, "ECONNRESET", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        ErrnoSignal(OsConstants.EPIPE, "EPIPE", StabilitySeverity.WARN, StabilityAction.NONE),
        ErrnoSignal(OsConstants.ENOTCONN, "ENOTCONN", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER),
        ErrnoSignal(OsConstants.EAGAIN, "EAGAIN", StabilitySeverity.INFO, StabilityAction.NONE),
        ErrnoSignal(OsConstants.EINTR, "EINTR", StabilitySeverity.INFO, StabilityAction.NONE),
        ErrnoSignal(OsConstants.ENOMEM, "ENOMEM", StabilitySeverity.CRITICAL, StabilityAction.PREFER_BLOCKING),
    ).associateBy { it.errno }

    fun signalForErrno(errno: Int?): StabilitySignal? {
        if (errno == null) return null
        val mapped = MAP[errno] ?: return StabilitySignal(
            "ERRNO_$errno",
            StabilitySeverity.WARN,
            StabilityAction.NONE,
        )
        return StabilitySignal(mapped.name, mapped.severity, mapped.action)
    }
}
