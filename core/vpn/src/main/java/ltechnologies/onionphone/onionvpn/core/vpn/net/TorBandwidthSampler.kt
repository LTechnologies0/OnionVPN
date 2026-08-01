package ltechnologies.onionphone.onionvpn.core.vpn.net

import android.net.TrafficStats
import hev.sockstun.TProxyService
import java.util.Locale
import kotlin.math.abs
import kotlin.math.max

/**
 * Fallback sampler for **aggregate Tor clearnet bandwidth** (OnionVPN UID).
 *
 * Prefer ControlPort `traffic/read|written` deltas (all circuits) in the foreground
 * service; this UID path is the last resort when control is unavailable.
 *
 * Tor (and DNSCrypt) run in our process UID and are [VpnService.Builder.addDisallowedApplication]
 * self-excluded, so their guard/middle/exit TCP shows up on [TrafficStats.getUidRxBytes] /
 * [TrafficStats.getUidTxBytes] — not on the TUN. App payload through hev is attributed to
 * other UIDs; [TProxyService.TProxyGetStats] is only a secondary "tunnel payload" hint.
 *
 * Counters cover **all** OR connections / circuits for this UID — never a single circuit.
 *
 * @see android.net.TrafficStats
 * @see android.net.VpnService
 */
class TorBandwidthSampler(
    private val uid: Int,
) {
    data class Sample(
        val downBps: Double,
        val upBps: Double,
        /** Primary label for the notification / Status widget. */
        val displayText: String,
        val source: Source,
    )

    enum class Source { TorUid, HevTun, Unavailable }

    private var lastRx = UNSUPPORTED
    private var lastTx = UNSUPPORTED
    private var lastAtMs = 0L

    fun reset() {
        lastRx = UNSUPPORTED
        lastTx = UNSUPPORTED
        lastAtMs = 0L
    }

    fun sample(): Sample {
        val now = System.currentTimeMillis()
        val elapsedSec = max(0.001, (now - lastAtMs) / 1000.0)

        val uidRx = TrafficStats.getUidRxBytes(uid)
        val uidTx = TrafficStats.getUidTxBytes(uid)
        val uidOk = uidRx != UNSUPPORTED && uidTx != UNSUPPORTED

        val (rx, tx, source) = if (uidOk) {
            Triple(uidRx, uidTx, Source.TorUid)
        } else {
            val hev = runCatching { TProxyService.TProxyGetStats() }.getOrNull()
            if (hev != null && hev.size >= 2) {
                Triple(hev[0], hev[1], Source.HevTun)
            } else {
                return Sample(0.0, 0.0, "Tor ▼ —  ▲ —", Source.Unavailable)
            }
        }

        val down = if (lastAtMs > 0 && lastRx != UNSUPPORTED && rx >= lastRx) {
            (rx - lastRx) / elapsedSec
        } else {
            0.0
        }
        val up = if (lastAtMs > 0 && lastTx != UNSUPPORTED && tx >= lastTx) {
            (tx - lastTx) / elapsedSec
        } else {
            0.0
        }

        lastRx = rx
        lastTx = tx
        lastAtMs = now

        val prefix = when (source) {
            Source.TorUid -> "Tor"
            Source.HevTun -> "TUN"
            Source.Unavailable -> "Tor"
        }
        return Sample(
            downBps = down,
            upBps = up,
            displayText = String.format(
                Locale.US,
                "%s ▼ %s  ▲ %s",
                prefix,
                formatRate(down),
                formatRate(up),
            ),
            source = source,
        )
    }

    private fun formatRate(bytesPerSec: Double): String {
        // Primary unit = Mbit/s (bits) so UI matches Speedtest / ISP labels.
        // TrafficStats / Tor counters are bytes — convert ×8.
        val bits = abs(bytesPerSec) * 8.0
        return when {
            bits >= 1_000_000 -> String.format(Locale.US, "%.1f Mbit/s", bits / 1_000_000.0)
            bits >= 1_000 -> String.format(Locale.US, "%.0f Kbit/s", bits / 1_000.0)
            else -> String.format(Locale.US, "%.0f bit/s", bits)
        }
    }

    companion object {
        /** [TrafficStats.UNSUPPORTED] as Long for UID byte counters. */
        private const val UNSUPPORTED = TrafficStats.UNSUPPORTED.toLong()
    }
}
