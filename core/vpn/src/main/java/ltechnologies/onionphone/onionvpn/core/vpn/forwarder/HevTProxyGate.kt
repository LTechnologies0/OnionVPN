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
 *
 * **Crash hardening (M7):** The native libhev-socks5-tunnel.so can SIGABRT in
 * `netif_add` during init if a stale worker is still in a bad state. We now:
 * 1. Always pre-Stop with a short grace period to let the native thread exit.
 * 2. Track native initialization state to detect orphaned workers.
 * 3. Add exponential backoff on repeated Start failures.
 */
internal object HevTProxyGate {
    private val lock = Any()
    @Volatile
    private var owner: Any? = null
    @Volatile
    private var nativeInitialized: Boolean = false
    @Volatile
    private var lastStartFailureMs: Long = 0
    @Volatile
    private var consecutiveFailures: Int = 0

    private const val MAX_CONSECUTIVE_FAILURES = 3
    private const val FAILURE_BACKOFF_BASE_MS = 500L

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

            // Pre-stop any orphaned native worker with grace period for thread cleanup.
            // This is critical: a crashed native thread may leave netif state inconsistent.
            if (cur == null || nativeInitialized) {
                runCatching { hev.sockstun.TProxyService.TProxyStopService() }
                    .onFailure { Timber.d(it, "TProxy pre-Start Stop") }
                // Give the native pthread time to fully exit (pthread_join not available).
                Thread.sleep(150)
                nativeInitialized = false
            }

            // Exponential backoff after repeated failures to avoid hammering a broken native state.
            if (consecutiveFailures > 0) {
                val backoff = FAILURE_BACKOFF_BASE_MS * (1 shl (consecutiveFailures - 1).coerceAtMost(5))
                val sinceLastFailure = System.currentTimeMillis() - lastStartFailureMs
                if (sinceLastFailure < backoff) {
                    Timber.w(
                        "TProxy Start backoff — failure #$consecutiveFailures, waiting ${backoff - sinceLastFailure}ms"
                    )
                    Thread.sleep(backoff - sinceLastFailure)
                }
            }

            var success = false
            try {
                start()
                success = true
                owner = token
                nativeInitialized = true
                consecutiveFailures = 0
                true
            } catch (error: Throwable) {
                lastStartFailureMs = System.currentTimeMillis()
                consecutiveFailures = (consecutiveFailures + 1).coerceAtMost(MAX_CONSECUTIVE_FAILURES)
                nativeInitialized = false
                owner = null
                Timber.e(error, "TProxy Start failed (consecutive=$consecutiveFailures)")
                throw error
            }
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
                if (owner === token) {
                    owner = null
                    // Don't clear nativeInitialized here — the native thread may still be
                    // shutting down. Next Start will pre-Stop and wait.
                }
            }
        }
    }

    /** Called when native worker is confirmed running (after successful Start). */
    fun markNativeInitialized() {
        nativeInitialized = true
    }

    /** Called when native worker has cleanly exited (after successful Stop). */
    fun markNativeStopped() {
        nativeInitialized = false
    }

    /** Reset failure counter on successful tunnel operation. */
    fun recordSuccess() {
        if (consecutiveFailures > 0) {
            Timber.i("TProxy failure streak broken (was $consecutiveFailures)")
            consecutiveFailures = 0
        }
    }
}
