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
 * **Cold-start ordering:** DNSCrypt starts before the TUN/onionmasq bootstrap in the
 * tunnel orchestrator, so the first DNSCrypt config still uses arti-mobile SOCKS +
 * DNSPort ([INTERIM_USES_ARTI_MOBILE]). After onionmasq is ready, call
 * [socksPortOrZero] — when non-zero, DNSCrypt may be restarted against the sidecar
 * (single TorClient cutover).
 */
object OnionmasqSocksSidecar {
    /** Until orchestrator reorders DNSCrypt after onionmasq ready, keep arti-mobile for bootstrap. */
    const val INTERIM_USES_ARTI_MOBILE = true

    /** Bound sidecar port, or 0 if onionmasq is not running / sidecar down. */
    fun socksPortOrZero(): Int {
        if (!OnionMasq.isRunning()) return 0
        return runCatching { OnionMasq.getSocksSidecarPort().toInt() }
            .onFailure { Timber.w(it, "getSocksSidecarPort") }
            .getOrDefault(0)
            .coerceAtLeast(0)
    }
}
