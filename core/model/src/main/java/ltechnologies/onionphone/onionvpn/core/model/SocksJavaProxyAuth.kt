package ltechnologies.onionphone.onionvpn.core.model

import java.net.Authenticator
import java.net.PasswordAuthentication

/**
 * Scoped SOCKS5 USERNAME/PASSWORD for Java [java.net.Proxy.Type.SOCKS] (OkHttp).
 *
 * Android/OkHttp do not take SOCKS credentials on [java.net.Proxy] — they call
 * [Authenticator]. Onionmasq sidecar and Arti IsolateSOCKSAuth reject empty tokens
 * (see ExitIpValidator 0.3.53, TorPathValidator Socks5Client).
 *
 * Global Authenticator is process-wide: lock + clear after each use.
 */
object SocksJavaProxyAuth {
    private val lock = Any()

    fun <T> withCredentials(user: String, pass: String, block: () -> T): T {
        require(user.isNotBlank() && pass.isNotBlank()) {
            "SOCKS5 username/password required for IsolateSOCKSAuth"
        }
        synchronized(lock) {
            // Android stubs omit Authenticator.getDefault() on some API levels.
            Authenticator.setDefault(
                object : Authenticator() {
                    override fun getPasswordAuthentication(): PasswordAuthentication? {
                        val proto = requestingProtocol ?: return null
                        if (!proto.startsWith("SOCKS", ignoreCase = true)) return null
                        return PasswordAuthentication(user, pass.toCharArray())
                    }
                },
            )
            try {
                return block()
            } finally {
                Authenticator.setDefault(null)
            }
        }
    }

    /** SessionGroup / IsolationToken probe role ([TunnelEndpoints.SOCKS_PROBE_*]). */
    fun <T> withProbe(block: () -> T): T =
        withCredentials(
            TunnelEndpoints.SOCKS_PROBE_USER,
            TunnelEndpoints.SOCKS_PROBE_PASS,
            block,
        )
}
