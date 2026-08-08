package ltechnologies.onionphone.onionvpn.diagnostics

import android.content.Context
import android.os.Debug
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import ltechnologies.onionphone.onionvpn.core.model.observability.DiagnosticsGate
import ltechnologies.onionphone.onionvpn.core.model.observability.MemoryHygiene
import ltechnologies.onionphone.onionvpn.core.model.observability.OpTrace
import ltechnologies.onionphone.onionvpn.core.model.observability.ProcFsParser
import ltechnologies.onionphone.onionvpn.core.model.stability.ProcessLogLevel

data class ResourceSnapshot(
    val timestampMs: Long = 0L,
    val heapUsedMb: Double = 0.0,
    val heapMaxMb: Double = 0.0,
    val nativeHeapAllocMb: Double = 0.0,
    val nativeHeapSizeMb: Double = 0.0,
    val vmRssMb: Double = 0.0,
    val vmSizeMb: Double = 0.0,
    val threads: Int = 0,
    val cpuPercent: Double = 0.0,
    val torChildRssMb: Double? = null,
    val libs: List<LibInfo> = emptyList(),
) {
    data class LibInfo(val name: String, val sizeKb: Long, val present: Boolean)

    fun summaryLine(): String = buildString {
        append("profiler rss=${"%.1f".format(vmRssMb)}MB")
        append(" heap=${"%.1f".format(heapUsedMb)}/${"%.1f".format(heapMaxMb)}MB")
        append(" native=${"%.1f".format(nativeHeapAllocMb)}MB")
        append(" threads=$threads")
        append(" cpu=${"%.0f".format(cpuPercent)}%")
        torChildRssMb?.let { append(" torRss=${"%.1f".format(it)}MB") }
        val missing = libs.count { !it.present }
        append(" libs=${libs.count { it.present }}/${libs.size}")
        if (missing > 0) append(" missing=$missing")
    }
}

/**
 * Samples JVM + process + native `.so` footprint while diagnostics are enabled.
 */
class NativeResourceProfiler(
    private val context: Context,
    private val scope: CoroutineScope,
    private val intervalMs: Long = DEFAULT_INTERVAL_MS,
    private val torChildPidProvider: () -> Int? = { null },
) {
    private val _snapshot = MutableStateFlow(ResourceSnapshot())
    val snapshot: StateFlow<ResourceSnapshot> = _snapshot.asStateFlow()

    private var job: Job? = null
    private var lastCpu: ProcFsParser.StatCpu? = null
    private var lastCpuAtMs: Long = 0L

    fun start() {
        if (!DiagnosticsGate.enabled()) return
        if (job?.isActive == true) return
        job = scope.launch {
            OpTrace.info(MODULE, "sampler start intervalMs=$intervalMs")
            while (isActive && DiagnosticsGate.enabled()) {
                val snap = sample()
                _snapshot.value = snap
                OpTrace.event(MODULE, snap.summaryLine(), ProcessLogLevel.DEBUG)
                MemoryHygiene.suggestGcIfPressure("profiler")
                delay(intervalMs)
            }
        }
    }

    fun stop() {
        val was = job
        job = null
        was?.cancel()
        if (was != null) {
            OpTrace.info(MODULE, "sampler stop")
        }
        lastCpu = null
        lastCpuAtMs = 0L
        // Drop last Connected sample so Status "Resources" does not stay open on Idle.
        _snapshot.value = ResourceSnapshot()
    }

    fun sampleNow(): ResourceSnapshot {
        val snap = sample()
        _snapshot.value = snap
        return snap
    }

    private fun sample(): ResourceSnapshot {
        val rt = Runtime.getRuntime()
        val heapUsed = (rt.totalMemory() - rt.freeMemory()) / (1024.0 * 1024.0)
        val heapMax = rt.maxMemory() / (1024.0 * 1024.0)
        val nativeAlloc = Debug.getNativeHeapAllocatedSize() / (1024.0 * 1024.0)
        val nativeSize = Debug.getNativeHeapSize() / (1024.0 * 1024.0)
        val status = runCatching {
            ProcFsParser.parseStatus(File("/proc/self/status").readText())
        }.getOrDefault(ProcFsParser.StatusMetrics())
        val cpuPct = sampleCpuPercent()
        val torPid = torChildPidProvider()
        val torRss = torPid?.let { pid ->
            runCatching {
                ProcFsParser.parseStatus(File("/proc/$pid/status").readText()).vmRssKb / 1024.0
            }.getOrNull()
        }
        return ResourceSnapshot(
            timestampMs = System.currentTimeMillis(),
            heapUsedMb = heapUsed,
            heapMaxMb = heapMax,
            nativeHeapAllocMb = nativeAlloc,
            nativeHeapSizeMb = nativeSize,
            vmRssMb = status.vmRssKb / 1024.0,
            vmSizeMb = status.vmSizeKb / 1024.0,
            threads = status.threads,
            cpuPercent = cpuPct,
            torChildRssMb = torRss,
            libs = listNativeLibs(),
        )
    }

    private fun sampleCpuPercent(): Double {
        val now = System.currentTimeMillis()
        val cpu = runCatching {
            ProcFsParser.parseStatCpu(File("/proc/self/stat").readText())
        }.getOrNull() ?: return 0.0
        val prev = lastCpu
        val prevAt = lastCpuAtMs
        lastCpu = cpu
        lastCpuAtMs = now
        if (prev == null || prevAt <= 0L) return 0.0
        val dtMs = (now - prevAt).coerceAtLeast(1L)
        val dTicks = (cpu.totalTicks - prev.totalTicks).coerceAtLeast(0L)
        // Android clock ticks typically 100 Hz → % = ticks/sec / cores * 100, simplify to
        // ticks * 10 / dtMs (approx % of one core at 100Hz).
        val hz = 100.0
        return ((dTicks / (dtMs / 1000.0)) / hz) * 100.0 /
            Runtime.getRuntime().availableProcessors().coerceAtLeast(1)
    }

    private fun listNativeLibs(): List<ResourceSnapshot.LibInfo> {
        val dir = File(context.applicationInfo.nativeLibraryDir)
        return TRACKED_LIBS.map { name ->
            val f = File(dir, name)
            ResourceSnapshot.LibInfo(
                name = name,
                sizeKb = if (f.isFile) f.length() / 1024L else 0L,
                present = f.isFile,
            )
        }
    }

    companion object {
        const val MODULE = "profiler"
        const val DEFAULT_INTERVAL_MS = 5_000L
        // Names must match jniLibs/*.so (Go PTs ship as libLyrebird / libConjure).
        val TRACKED_LIBS = listOf(
            "libtor.so",
            "libarti_mobile_ex.so",
            "libhev-socks5-tunnel.so",
            "libdnscrypt-proxy.so",
            "libLyrebird.so",
            "libConjure.so",
        )
    }
}
