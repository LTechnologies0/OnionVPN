package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import android.system.OsConstants
import java.io.File
import java.net.InetSocketAddress
import java.util.concurrent.locks.LockSupport
import timber.log.Timber

/**
 * Resolves the UID that owns an outbound socket matching the TUN packet 5-tuple.
 *
 * API 29+: [ConnectivityManager.getConnectionOwnerUid] (must be called while this app's
 * [android.net.VpnService] is the active VPN — SecurityException otherwise).
 *
 * First SYN often races the kernel connection table → [Process.INVALID_UID]. We retry
 * briefly (NetGuard / PCAPdroid pattern) before giving up.
 *
 * Older: best-effort `/proc/net/tcp|udp` scan (blocked on API 29+ for normal apps).
 */
class ConnectionOwnerResolver(context: Context) {
    private val appContext = context.applicationContext
    private val connectivity =
        appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    fun resolveUid(info: IpPacketInfo): Int {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return resolveApi29WithRetry(info)
        }
        return resolveProcNet(info)
    }

    private fun resolveApi29WithRetry(info: IpPacketInfo): Int {
        var last = Process.INVALID_UID
        repeat(MAX_ATTEMPTS) { attempt ->
            last = resolveApi29Once(info)
            if (isValidUid(last)) return last
            if (attempt < MAX_ATTEMPTS - 1) {
                LockSupport.parkNanos(RETRY_PARK_NS)
            }
        }
        if (last == Process.INVALID_UID) {
            Timber.d(
                "getConnectionOwnerUid miss %s %s:%d → %s:%d after %d tries",
                IpPacketParser.protocolLabel(info.protocol),
                info.srcIp,
                info.srcPort,
                info.dstIp,
                info.dstPort,
                MAX_ATTEMPTS,
            )
        }
        return last
    }

    private fun resolveApi29Once(info: IpPacketInfo): Int {
        return try {
            val protocol = when (info.protocol) {
                IpPacketParser.PROTO_TCP -> OsConstants.IPPROTO_TCP
                IpPacketParser.PROTO_UDP -> OsConstants.IPPROTO_UDP
                else -> return Process.INVALID_UID
            }
            val local = InetSocketAddress(info.srcIp, info.srcPort)
            val remote = InetSocketAddress(info.dstIp, info.dstPort)
            @Suppress("NewApi")
            connectivity.getConnectionOwnerUid(protocol, local, remote)
        } catch (error: SecurityException) {
            // Caller is not the active VpnService for this user.
            Timber.w(error, "getConnectionOwnerUid denied — VPN not active owner?")
            Process.INVALID_UID
        } catch (error: Exception) {
            Timber.w(error, "getConnectionOwnerUid failed")
            Process.INVALID_UID
        }
    }

    /**
     * Very rough fallback: match remote address:port in /proc/net tables.
     * Local port matching preferred when present.
     */
    private fun resolveProcNet(info: IpPacketInfo): Int {
        val file = when (info.protocol) {
            IpPacketParser.PROTO_TCP -> File("/proc/net/tcp")
            IpPacketParser.PROTO_UDP -> File("/proc/net/udp")
            else -> return Process.INVALID_UID
        }
        if (!file.canRead()) return Process.INVALID_UID
        val remoteHex = ipv4PortHex(info.dstIp, info.dstPort)
        val localHex = ipv4PortHex(info.srcIp, info.srcPort)
        return try {
            file.bufferedReader().useLines { lines ->
                lines.drop(1).forEach { line ->
                    val parts = line.trim().split(Regex("\\s+"))
                    if (parts.size < 8) return@forEach
                    val local = parts[1]
                    val remote = parts[2]
                    if (remote.equals(remoteHex, ignoreCase = true) &&
                        (local.equals(localHex, ignoreCase = true) || info.isUdp)
                    ) {
                        return@useLines parts[7].toIntOrNull() ?: Process.INVALID_UID
                    }
                }
                Process.INVALID_UID
            }
        } catch (error: Exception) {
            Timber.w(error, "proc net uid lookup failed")
            Process.INVALID_UID
        }
    }

    /** Linux /proc: little-endian hex IP + port. */
    private fun ipv4PortHex(ip: String, port: Int): String {
        val octets = ip.split('.').mapNotNull { it.toIntOrNull() }
        if (octets.size != 4) return ""
        val ipHex = String.format(
            "%02X%02X%02X%02X",
            octets[3],
            octets[2],
            octets[1],
            octets[0],
        )
        val portHex = String.format("%04X", port)
        return "$ipHex:$portHex"
    }

    companion object {
        private const val MAX_ATTEMPTS = 10
        /** ~2ms between retries; total budget ~20ms on a cold SYN miss. */
        private const val RETRY_PARK_NS = 2_000_000L

        fun isValidUid(uid: Int): Boolean =
            uid != Process.INVALID_UID && uid >= 0
    }
}
