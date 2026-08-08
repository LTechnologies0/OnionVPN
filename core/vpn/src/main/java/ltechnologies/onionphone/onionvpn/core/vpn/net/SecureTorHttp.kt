package ltechnologies.onionphone.onionvpn.core.vpn.net

import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient

/**
 * Shared OkHttp hardening for integrity-sensitive Tor/probe HTTPS fetches.
 *
 * - No HTTP(S) redirects (open redirect / host-swap via hostile exit MitM)
 * - TLS 1.2+ only ([ConnectionSpec.MODERN_TLS]) — never CLEARTEXT
 *
 * Does not install a custom TrustManager; platform + NSC remain the trust store.
 * Certificate pinning is intentionally omitted (rotation would break the tunnel UX).
 */
object SecureTorHttp {
    fun OkHttpClient.Builder.applyTorClientHardening(): OkHttpClient.Builder = apply {
        followRedirects(false)
        followSslRedirects(false)
        connectionSpecs(listOf(ConnectionSpec.MODERN_TLS))
    }
}
