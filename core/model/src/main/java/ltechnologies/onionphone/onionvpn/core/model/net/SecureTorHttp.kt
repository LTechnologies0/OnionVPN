package ltechnologies.onionphone.onionvpn.core.model.net

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
 *
 * Lives in `:core:model` so `:core:tor`, `:core:vpn`, `:core:validation`, and `:app`
 * share one CVE-hardening path without cross-module cycles.
 */
object SecureTorHttp {
    fun OkHttpClient.Builder.applyTorClientHardening(): OkHttpClient.Builder = apply {
        followRedirects(false)
        followSslRedirects(false)
        connectionSpecs(listOf(ConnectionSpec.MODERN_TLS))
    }
}
