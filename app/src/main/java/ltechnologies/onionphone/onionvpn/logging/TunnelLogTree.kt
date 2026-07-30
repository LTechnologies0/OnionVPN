package ltechnologies.onionphone.onionvpn.logging

import android.util.Log
import timber.log.Timber

/** Plants app Timber messages into [TunnelLogBuffer]; ERROR/ASSERT marked as errors. */
class TunnelLogTree : Timber.Tree() {
    override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
        // Tor / DNSCrypt have dedicated buffers — avoid duplicating them under OnionVPN.
        if (tag == "tor" || tag == "dnscrypt") return

        val prefix = tag?.let { "[$it] " }.orEmpty()
        val text = if (t != null) "$prefix$message (${t.message})" else "$prefix$message"
        // Keyword heuristics only for WARN+ — DEBUG lines like "DNSCrypt probe … timeout"
        // must not light up as errors in the UI.
        val isError = priority >= Log.ERROR ||
            (priority >= Log.WARN && ProcessLogSeverity.isError(LogSource.APP, text))
        TunnelLogBuffer.append(LogSource.APP, text, isError = isError)
    }
}
