package ltechnologies.onionphone.onionvpn.core.vpn.net

import android.net.TrafficStats
import hev.sockstun.TProxyService
import java.util.Locale
import kotlin.math.abs
import kotlin.math.max

/**
 * Measures **Tor clearnet bandwidth** for OnionVPN's UID.
 *
 * Tor (and DNSCrypt) run in our process UID and are [VpnService.Builder.addDisallowedApplication]
 * self-excluded, so their guard/middle/exit TCP shows up on [TrafficStats.getUidRxBytes] /
 * [TrafficStats.getUidTxBytes] — not on the TUN. App payload through hev is attributed to
 * other UIDs; [TProxyService.TProxyGetStats] is only a secondary "tunnel payload" hint.
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
        val a = abs(bytesPerSec)
        return when {
            a >= 1_048_576 -> String.format(Locale.US, "%.1f MB/s", bytesPerSec / 1_048_576.0)
            a >= 1024 -> String.format(Locale.US, "%.1f KB/s", bytesPerSec / 1024.0)
            else -> String.format(Locale.US, "%.0f B/s", bytesPerSec)
        }
    }

    companion object {
        /** [TrafficStats.UNSUPPORTED] as Long for UID byte counters. */
        private const val UNSUPPORTED = TrafficStats.UNSUPPORTED.toLong()
    }
}
