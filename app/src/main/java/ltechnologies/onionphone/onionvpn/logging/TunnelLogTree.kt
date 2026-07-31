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
        // VERBOSE/TRACE is for expected handshake noise (PAC EOF, SETEVENTS 552, DNS probes).
        if (priority < Log.DEBUG) return

        val prefix = tag?.let { "[$it] " }.orEmpty()
        val text = if (t != null) "$prefix$message (${t.message})" else "$prefix$message"
        val signal = ProcessLogSeverity.classifyApp(priority, text)
        TunnelLogBuffer.append(LogSource.APP, text, severity = signal.severity)
    }
}
