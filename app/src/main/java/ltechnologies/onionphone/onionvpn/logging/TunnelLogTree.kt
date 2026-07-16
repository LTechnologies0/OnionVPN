package ltechnologies.onionphone.onionvpn.logging

import timber.log.Timber

/** Plants app Timber messages into [TunnelLogBuffer]. */
class TunnelLogTree : Timber.Tree() {
    override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
        val prefix = tag?.let { "[$it] " }.orEmpty()
        val text = if (t != null) "$prefix$message (${t.message})" else "$prefix$message"
        TunnelLogBuffer.append(LogSource.APP, text)
    }
}
