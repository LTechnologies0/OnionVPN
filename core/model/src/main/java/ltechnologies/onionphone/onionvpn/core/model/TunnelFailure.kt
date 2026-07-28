package ltechnologies.onionphone.onionvpn.core.model

import android.system.ErrnoException
import android.system.OsConstants
import java.io.InterruptedIOException
import java.net.BindException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.PortUnreachableException
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.CancellationException

/**
 * Typed tunnel failures mapped from Tor / VpnService / DNSCrypt / TCP·UDP errno-class errors.
 *
 * [userMessage] is safe for Status UI (no cookie bytes / paths with secrets).
 * [stopTor] / [preferBlocking] drive [TunnelPhase.Error] vs kill-switch Blocking.
 */
sealed class TunnelFailure(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {
    /** Tor binary missing, not executable, or process died at spawn. */
    class TorBinary(detail: String, cause: Throwable? = null) :
        TunnelFailure(detail, cause)

    /** ControlSocket / cookie / AUTHENTICATE / reader drop. */
    class TorControl(detail: String, cause: Throwable? = null) :
        TunnelFailure(detail, cause)

    /** Bootstrap / SOCKS·DNSPort listeners not ready in time. */
    class TorBootstrap(val progress: Int, detail: String, cause: Throwable? = null) :
        TunnelFailure(detail, cause)

    /** dnscrypt-proxy start, listen, or upstream-via-Tor. */
    class DnsCrypt(val stage: String, detail: String, cause: Throwable? = null) :
        TunnelFailure(detail, cause)

    /** VpnService.prepare / Builder.establish / permission. */
    class VpnEstablish(detail: String, cause: Throwable? = null) :
        TunnelFailure(detail, cause)

    /** hev / TunDnsMux forwarder died while Connected. */
    class ForwarderDead(detail: String, cause: Throwable? = null) :
        TunnelFailure(detail, cause)

    /** Soft validation / unknown — keep Tor when possible. */
    class Soft(detail: String, cause: Throwable? = null) :
        TunnelFailure(detail, cause)

    val userMessage: String
        get() = sanitizeForUi(message ?: "Unknown tunnel error")

    /** Tear down Tor process on this failure. */
    val stopTor: Boolean
        get() = when (this) {
            is TorBinary, is TorControl, is TorBootstrap -> true
            is DnsCrypt, is VpnEstablish, is ForwarderDead, is Soft -> false
        }

    companion object {
        private val ABS_PATH = Regex("""(/data/|/storage/|/sdcard/|file://)[^\s)]+""")

        fun sanitizeForUi(raw: String): String =
            ABS_PATH.replace(raw, "[path]").take(280)

        /**
         * Maps OS / Tor / DNSCrypt throwables into a [TunnelFailure].
         * Prefer wrapping at catch sites; use this as a last-resort classifier.
         */
        fun fromThrowable(
            error: Throwable,
            context: String = "",
            bootstrapProgress: Int = 0,
        ): TunnelFailure {
            if (error is TunnelFailure) return error
            if (error is CancellationException) throw error

            val errno = (error as? ErrnoException)?.errno
                ?: ((error.cause as? ErrnoException)?.errno)
            val raw = sequenceOf(error.message, error.cause?.message, context)
                .filterNotNull()
                .joinToString(" — ")
                .ifBlank { error.javaClass.simpleName }

            when (errno) {
                OsConstants.ENOENT ->
                    return TorBinary("Component missing on disk ($raw)", error)
                OsConstants.EACCES, OsConstants.EPERM ->
                    return TorBinary("Permission denied starting component ($raw)", error)
                OsConstants.EADDRINUSE ->
                    return Soft("Port already in use ($raw)", error)
                OsConstants.ECONNREFUSED ->
                    return classifyRefused(raw, error, context)
                OsConstants.ETIMEDOUT ->
                    return Soft("Network timeout ($raw)", error)
                OsConstants.ENETUNREACH, OsConstants.EHOSTUNREACH ->
                    return Soft("Network unreachable ($raw)", error)
            }

            return when (error) {
                is BindException ->
                    Soft("Bind failed — port in use ($raw)", error)
                is ConnectException ->
                    classifyRefused(raw, error, context)
                is SocketTimeoutException, is InterruptedIOException ->
                    Soft("Socket timeout ($raw)", error)
                is PortUnreachableException ->
                    Soft("Port unreachable ($raw)", error)
                is NoRouteToHostException ->
                    Soft("No route to host ($raw)", error)
                is UnknownHostException ->
                    Soft("DNS/host unknown ($raw)", error)
                is SecurityException ->
                    VpnEstablish("VPN/security permission denied ($raw)", error)
                is SocketException ->
                    classifySocket(raw, error, context)
                else -> classifyByMessage(raw, error, context, bootstrapProgress)
            }
        }

        private fun classifyRefused(
            raw: String,
            error: Throwable,
            context: String,
        ): TunnelFailure {
            val c = "$context $raw".lowercase()
            return when {
                "control" in c || "cookie" in c || "authenticate" in c ->
                    TorControl("Tor control connection refused ($raw)", error)
                "dnscrypt" in c || "5354" in c || "dns" in c ->
                    DnsCrypt("listen", "DNSCrypt listener refused ($raw)", error)
                "socks" in c || "9050" in c ->
                    TorBootstrap(0, "Tor SOCKS refused ($raw)", error)
                else -> Soft("Connection refused ($raw)", error)
            }
        }

        private fun classifySocket(
            raw: String,
            error: Throwable,
            context: String,
        ): TunnelFailure {
            val c = "$context $raw".lowercase()
            return when {
                "broken pipe" in c || "connection reset" in c ->
                    Soft("Socket reset ($raw)", error)
                "permission" in c ->
                    VpnEstablish("Socket permission denied ($raw)", error)
                else -> Soft("Socket error ($raw)", error)
            }
        }

        private fun classifyByMessage(
            raw: String,
            error: Throwable,
            context: String,
            bootstrapProgress: Int,
        ): TunnelFailure {
            val c = "$context $raw".lowercase()
            return when {
                "binary missing" in c || "not executable" in c ||
                    "libtor" in c || "dnscrypt-proxy" in c && "missing" in c ->
                    TorBinary(raw, error)
                "cookie" in c || "control socket" in c || "authenticate" in c ||
                    "control not connected" in c || "control command" in c ||
                    "control disconnected" in c || "control reader" in c ->
                    TorControl(raw, error)
                "bootstrap" in c || "socks" in c && "listen" in c ||
                    "dnsport" in c || "exited before bootstrap" in c ->
                    TorBootstrap(bootstrapProgress, raw, error)
                "dnscrypt" in c ->
                    DnsCrypt(stageFrom(c), raw, error)
                "vpn" in c || "establish()" in c || "permission not granted" in c ||
                    "prepare" in c ->
                    VpnEstablish(raw, error)
                "hev" in c || "forwarder" in c || "tundnsmux" in c || "mux" in c ->
                    ForwarderDead(raw, error)
                else -> Soft(raw, error)
            }
        }

        private fun stageFrom(c: String): String = when {
            "upstream" in c || "example" in c || "resolve" in c -> "upstream"
            "listen" in c || "stub" in c -> "listen"
            else -> "start"
        }

        /** Compact user line from any throwable (safe for Status / notifications). */
        fun userMessageOf(error: Throwable, context: String = ""): String =
            fromThrowable(error, context).userMessage
    }
}
