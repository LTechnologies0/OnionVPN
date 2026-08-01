package ltechnologies.onionphone.onionvpn.core.model.observability

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

/**
 * Rate-limited JVM GC hints + optional soft-cache trim callbacks.
 *
 * Do **not** call from TUN/DNS/SOCKS hot paths — only after heavy one-shot work
 * (Tor/DNSCrypt stop, reputation merge, tunnel teardown) or under OS memory pressure.
 * `System.gc()` is a hint; ART may ignore it. Clearing app caches does more real work.
 */
object MemoryHygiene {
    /** Minimum gap between GC hints (avoids thrashing under reconnect storms). */
    const val MIN_INTERVAL_MS = 30_000L

    /** Trigger [suggestGcIfPressure] when used/max heap exceeds this ratio. */
    const val HEAP_PRESSURE_RATIO = 0.72

    private val lastGcAtMs = AtomicLong(0L)
    private val trimListeners = CopyOnWriteArrayList<(TrimLevel) -> Unit>()

    enum class TrimLevel {
        /** UI hidden / moderate — drop transient UI caches only. */
        SOFT,
        /** Running low / critical — clear recoverable runtime caches. */
        HARD,
        /** Process about to be killed / complete — aggressive cleanup. */
        COMPLETE,
    }

    fun heapUsedBytes(): Long {
        val rt = Runtime.getRuntime()
        return (rt.totalMemory() - rt.freeMemory()).coerceAtLeast(0L)
    }

    fun heapMaxBytes(): Long = Runtime.getRuntime().maxMemory().coerceAtLeast(1L)

    fun heapUsageRatio(): Double = heapUsedBytes().toDouble() / heapMaxBytes().toDouble()

    fun addTrimListener(listener: (TrimLevel) -> Unit) {
        trimListeners.addIfAbsent(listener)
    }

    fun removeTrimListener(listener: (TrimLevel) -> Unit) {
        trimListeners.remove(listener)
    }

    /** Notify listeners then optionally hint GC. */
    fun onTrim(level: TrimLevel) {
        for (listener in trimListeners) {
            runCatching { listener(level) }
        }
        when (level) {
            TrimLevel.SOFT -> suggestGcIfPressure("trim_soft")
            TrimLevel.HARD -> suggestGc("trim_hard", force = false)
            TrimLevel.COMPLETE -> suggestGc("trim_complete", force = true)
        }
    }

    /**
     * After large transient allocations (blocklists, bootstrap, process stop).
     * @return true if a GC hint was issued this call.
     */
    fun afterHeavyWork(reason: String): Boolean = suggestGc(reason, force = false)

    /** GC hint only when heap usage is elevated. */
    fun suggestGcIfPressure(reason: String = "heap_pressure"): Boolean {
        if (heapUsageRatio() < HEAP_PRESSURE_RATIO) return false
        return suggestGc(reason, force = false)
    }

    fun suggestGc(reason: String, force: Boolean = false): Boolean {
        val now = System.currentTimeMillis()
        while (true) {
            val last = lastGcAtMs.get()
            if (!force && now - last < MIN_INTERVAL_MS) return false
            if (lastGcAtMs.compareAndSet(last, now)) break
        }
        System.gc()
        if (DiagnosticsGate.enabled()) {
            OpTrace.debug(
                "memory",
                "gc hint reason=$reason heap=${"%.0f".format(heapUsageRatio() * 100)}%",
            )
        }
        return true
    }

    /** Test hook — resets rate limiter. */
    internal fun resetForTests() {
        lastGcAtMs.set(0L)
    }
}
