package ltechnologies.onionphone.onionvpn.core.model.observability

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Master switch for TRACE→ERROR diagnostics and resource profiling.
 *
 * Diagnostics are **enabled** when [noLogsEnabled] is false.
 * Release default: no-logs ON (silent). Debug default: no-logs OFF (verbose).
 */
object DiagnosticsGate {
    private val _noLogsEnabled = MutableStateFlow(true)
    private val _diagnosticsEnabled = MutableStateFlow(false)

    /** Privacy switch from Settings — when true, all diagnostic sinks no-op. */
    val noLogsEnabled: StateFlow<Boolean> = _noLogsEnabled.asStateFlow()

    /** Inverse of [noLogsEnabled] — true when logging/profiling may run. */
    val diagnosticsEnabled: StateFlow<Boolean> = _diagnosticsEnabled.asStateFlow()

    fun enabled(): Boolean = _diagnosticsEnabled.value

    fun isNoLogs(): Boolean = _noLogsEnabled.value

    /**
     * Apply preference. Call from prefs collector / Application startup.
     */
    fun setNoLogsEnabled(noLogs: Boolean) {
        _noLogsEnabled.value = noLogs
        _diagnosticsEnabled.value = !noLogs
        if (noLogs) {
            onDisabled?.invoke()
        } else {
            onEnabled?.invoke()
        }
    }

    /** Optional hooks (clear buffers, start/stop profiler) set by the app layer. */
    @Volatile
    var onEnabled: (() -> Unit)? = null

    @Volatile
    var onDisabled: (() -> Unit)? = null
}
