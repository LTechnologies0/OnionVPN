package ltechnologies.onionphone.onionvpn.logging

import android.util.Log
import ltechnologies.onionphone.onionvpn.core.model.observability.DiagnosticsGate
import timber.log.Timber

/** Plants app Timber messages into [TunnelLogBuffer] with TRACE→CRITICAL severity. */
class TunnelLogTree : Timber.Tree() {
    override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
        if (!DiagnosticsGate.enabled()) return
        // Tor / DNSCrypt have dedicated buffers — avoid duplicating them under OnionVPN.
        if (tag == "tor" || tag == "dnscrypt" || tag == "arti") return
        // Accept VERBOSE→ASSERT (TRACE→CRITICAL). DiagnosticsGate already gates this tree;
        // no-logs mode keeps the UI silent. Prefer Timber.v / OpTrace.trace for handshake noise.

        val prefix = tag?.let { "[$it] " }.orEmpty()
        val text = if (t != null) "$prefix$message (${t.message})" else "$prefix$message"
        val signal = ProcessLogSeverity.classifyApp(priority, text)
        TunnelLogBuffer.append(LogSource.APP, text, severity = signal.severity)
    }
}
