package ltechnologies.onionphone.onionvpn.service.lifecycle

import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlStatus
import ltechnologies.onionphone.onionvpn.core.vpn.net.TorBandwidthSampler
import ltechnologies.onionphone.onionvpn.service.TunnelSnapshotBuilder

/**
 * Nested throughput formatter: traffic/read|written deltas → BW event → UID TrafficStats.
 */
internal class TunnelThroughputTracker(
    private val bandwidthSampler: TorBandwidthSampler,
) {
    private var lastTrafficReadBytes = -1L
    private var lastTrafficWriteBytes = -1L
    private var lastTrafficAtMs = 0L

    var displayText: String = ""
        private set

    fun reset() {
        bandwidthSampler.reset()
        displayText = ""
        lastTrafficReadBytes = -1L
        lastTrafficWriteBytes = -1L
        lastTrafficAtMs = 0L
    }

    fun sampleUidFallback(): String {
        displayText = bandwidthSampler.sample().displayText
        return displayText
    }

    fun formatAggregate(
        st: TorControlStatus,
        builtCircuits: Int = st.builtCircuits,
    ): String {
        val now = System.currentTimeMillis()
        var trafficDown = 0L
        var trafficUp = 0L
        if (lastTrafficAtMs > 0L &&
            lastTrafficReadBytes >= 0L &&
            st.readBytes >= lastTrafficReadBytes &&
            st.writeBytes >= lastTrafficWriteBytes
        ) {
            val elapsedSec = ((now - lastTrafficAtMs).coerceAtLeast(1L)) / 1000.0
            trafficDown = ((st.readBytes - lastTrafficReadBytes) / elapsedSec).toLong()
            trafficUp = ((st.writeBytes - lastTrafficWriteBytes) / elapsedSec).toLong()
        }
        lastTrafficReadBytes = st.readBytes
        lastTrafficWriteBytes = st.writeBytes
        lastTrafficAtMs = now

        val down: Long
        val up: Long
        when {
            trafficDown > 0L || trafficUp > 0L -> {
                down = trafficDown
                up = trafficUp
            }
            st.lastBwReadPerSec > 0L || st.lastBwWritePerSec > 0L -> {
                down = st.lastBwReadPerSec
                up = st.lastBwWritePerSec
            }
            else -> {
                displayText = "${bandwidthSampler.sample().displayText}  · $builtCircuits circuits"
                return displayText
            }
        }
        displayText = "Tor ▼ ${TunnelSnapshotBuilder.formatRate(down)}  ▲ ${TunnelSnapshotBuilder.formatRate(up)}" +
            "  · $builtCircuits circuits"
        return displayText
    }
}
