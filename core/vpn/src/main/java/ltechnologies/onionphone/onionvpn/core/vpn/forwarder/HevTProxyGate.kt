package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import timber.log.Timber

/**
 * Process-wide ownership for hev-socks5-tunnel's singleton TProxy JNI.
 *
 * Native [hev.sockstun.TProxyService.TProxyStartService] silently no-ops when already
 * running (B03 C2). Serialize Start/Stop so HEV_SOCKS and Onionmasq Automap never race
 * a second Start against a live orphan worker.
 *
 * **Shared Automap+LAN (ONIONMASQ):** a second dedicated LAN hev is impossible while
 * TProxy is process-global — [TunDnsMux] routes both Automap SOCKS5A and ALLOW_LAN
 * through the same automapHevFd → SocksUidBridge (C2). Do not dual-Start.
 */
internal object HevTProxyGate {
    private val lock = Any()
    @Volatile
    private var owner: Any? = null

    /**
     * @return false if another owner holds TProxy — caller must [onFatal]/rollback.
     */
    fun startExclusive(token: Any, start: () -> Unit): Boolean =
        synchronized(lock) {
            val cur = owner
            if (cur != null && cur !== token) {
                Timber.e(
                    "TProxy Start refused — already owned (token mismatch). " +
                        "Silent native no-op would blackhole the new socketpair.",
                )
                return false
            }
            // Orphan native worker (owner cleared after crash/partial Stop) makes the next
            // Start a silent no-op — Stop first when we believe TProxy is free (W5-02 F1).
            if (cur == null) {
                runCatching { hev.sockstun.TProxyService.TProxyStopService() }
                    .onFailure { Timber.d(it, "TProxy pre-Start Stop (no prior owner)") }
            }
            start()
            owner = token
            true
        }

    fun stopIfOwner(token: Any, stop: () -> Unit) {
        synchronized(lock) {
            if (owner != null && owner !== token) {
                Timber.w("TProxy Stop ignored — not owner")
                return
            }
            try {
                stop()
            } finally {
                if (owner === token) owner = null
            }
        }
    }
}
