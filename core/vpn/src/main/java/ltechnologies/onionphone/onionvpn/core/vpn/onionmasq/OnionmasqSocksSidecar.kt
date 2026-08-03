package ltechnologies.onionphone.onionvpn.core.vpn.onionmasq

import org.torproject.onionmasq.OnionMasq
import timber.log.Timber

/**
 * DNSCrypt / probe SOCKS sidecar for the onionmasq data plane.
 *
 * Tor VPN’s onionmasq does not expose a SOCKS listener by default. OnionVPN patches
 * `onionmasq-mobile` to listen on loopback SOCKS using the *same* `TorClient`, mapping
 * SOCKS user/pass → `StreamPrefs` IsolationToken (`dnscrypt` / `probe`).
 *
 * **Cold-start ordering (single TorClient):** Blocking TUN → onionmasq Connected TUN →
 * wait ready + sidecar → [SocksDnsBootstrapRelay] TCP+UDP on allocated DNSPort → DNSCrypt
 * `force_tcp` + proxy=@sidecar (no arti-mobile; SOCKS RESOLVE + DoH fallback).
 */
object OnionmasqSocksSidecar {
    /**
     * Always false after cutover — arti-mobile must not run on the ONIONMASQ plane.
     * Kept as a named constant so NEWNYM / docs can branch explicitly.
     */
    const val INTERIM_USES_ARTI_MOBILE = false

    /** Bound sidecar port, or 0 if onionmasq is not running / sidecar down. */
    fun socksPortOrZero(): Int {
        // OnionMasq.isRunning()/getSocksSidecarPort are Java-hardened for pre-init,
        // but still avoid probing when the helper reports uninitialized.
        if (!OnionMasq.isInitialized() || !OnionMasq.isRunning()) return 0
        return runCatching { OnionMasq.getSocksSidecarPort().toInt() }
            .onFailure { Timber.w(it, "getSocksSidecarPort") }
            .getOrDefault(0)
            .coerceAtLeast(0)
    }

    /** Wait until sidecar binds (OnionMasq.start publishes port after listen). */
    suspend fun awaitPort(timeoutMs: Long = 30_000L, pollMs: Long = 200L): Int {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val p = socksPortOrZero()
            if (p > 0) return p
            kotlinx.coroutines.delay(pollMs)
        }
        return 0
    }
}
