package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.system.OsConstants
import java.io.File
import java.net.InetSocketAddress
import timber.log.Timber

/**
 * Resolves the UID that owns an outbound socket matching the TUN packet 5-tuple.
 * API 29+: [ConnectivityManager.getConnectionOwnerUid].
 * Older: best-effort `/proc/net/tcp|udp` scan (fragile).
 */
class ConnectionOwnerResolver(context: Context) {
    private val connectivity =
        context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    fun resolveUid(info: IpPacketInfo): Int {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return resolveApi29(info)
        }
        return resolveProcNet(info)
    }

    private fun resolveApi29(info: IpPacketInfo): Int {
        return try {
            val protocol = when (info.protocol) {
                IpPacketParser.PROTO_TCP -> OsConstants.IPPROTO_TCP
                IpPacketParser.PROTO_UDP -> OsConstants.IPPROTO_UDP
                else -> return -1
            }
            val local = InetSocketAddress(info.srcIp, info.srcPort)
            val remote = InetSocketAddress(info.dstIp, info.dstPort)
            @Suppress("NewApi")
            connectivity.getConnectionOwnerUid(protocol, local, remote)
        } catch (error: Exception) {
            Timber.w(error, "getConnectionOwnerUid failed")
            -1
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
            else -> return -1
        }
        if (!file.canRead()) return -1
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
                        return@useLines parts[7].toIntOrNull() ?: -1
                    }
                }
                -1
            }
        } catch (error: Exception) {
            Timber.w(error, "proc net uid lookup failed")
            -1
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
}
