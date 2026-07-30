package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import android.system.OsConstants
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import timber.log.Timber

/**
 * Resolves the UID that owns an outbound socket matching the TUN packet 5-tuple.
 *
 * API 29+: [ConnectivityManager.getConnectionOwnerUid] (must be called while this app's
 * [android.net.VpnService] is the active VPN — SecurityException otherwise).
 *
 * Hot path uses a **single** attempt — never parks the TUN reader thread. First SYN
 * races are acceptable as "unknown" and re-checked on the next SYN.
 *
 * Addresses are built from int IPs (no dotted-string parse) with ThreadLocal scratch bytes.
 */
class ConnectionOwnerResolver(context: Context) {
    private val appContext = context.applicationContext
    private val connectivity =
        appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    fun resolveUid(info: IpPacketInfo): Int {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return resolveApi29Once(info)
        }
        return resolveProcNet(info)
    }

    /**
     * UID of the peer that connected to an accepted loopback server socket (PAC SOCKS).
     * Uses the app's 5-tuple view: local=peer ephemeral, remote=listen port.
     */
    fun resolveAcceptedClientUid(client: Socket): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return Process.INVALID_UID
        }
        val peer = client.remoteSocketAddress as? InetSocketAddress ?: return Process.INVALID_UID
        val local = client.localSocketAddress as? InetSocketAddress ?: return Process.INVALID_UID
        repeat(PAC_UID_RETRY) { attempt ->
            val uid = try {
                @Suppress("NewApi")
                connectivity.getConnectionOwnerUid(OsConstants.IPPROTO_TCP, peer, local)
            } catch (error: SecurityException) {
                Timber.w(error, "getConnectionOwnerUid denied for PAC client")
                return Process.INVALID_UID
            } catch (error: Exception) {
                Timber.w(error, "getConnectionOwnerUid failed for PAC client")
                Process.INVALID_UID
            }
            if (isValidUid(uid)) return uid
            if (attempt < PAC_UID_RETRY - 1) {
                try {
                    Thread.sleep(PAC_UID_SLEEP_MS)
                } catch (_: InterruptedException) {
                    return Process.INVALID_UID
                }
            }
        }
        return Process.INVALID_UID
    }

    private fun resolveApi29Once(info: IpPacketInfo): Int {
        return try {
            val protocol = when (info.protocol) {
                IpPacketParser.PROTO_TCP -> OsConstants.IPPROTO_TCP
                IpPacketParser.PROTO_UDP -> OsConstants.IPPROTO_UDP
                else -> return Process.INVALID_UID
            }
            val local: InetSocketAddress
            val remote: InetSocketAddress
            if (info.isIpv6) {
                local = InetSocketAddress(InetAddress.getByName(info.srcIp), info.srcPort)
                remote = InetSocketAddress(InetAddress.getByName(info.dstIp), info.dstPort)
            } else {
                val scratch = addressScratch.get()
                local = socketAddress(info.srcIpInt, info.srcPort, scratch.localBytes)
                remote = socketAddress(info.dstIpInt, info.dstPort, scratch.remoteBytes)
            }
            @Suppress("NewApi")
            connectivity.getConnectionOwnerUid(protocol, local, remote)
        } catch (error: SecurityException) {
            Timber.w(error, "getConnectionOwnerUid denied — VPN not active owner?")
            Process.INVALID_UID
        } catch (error: Exception) {
            Timber.w(error, "getConnectionOwnerUid failed")
            Process.INVALID_UID
        }
    }

    private fun socketAddress(ip: Int, port: Int, bytes: ByteArray): InetSocketAddress {
        IpPacketParser.ipv4Bytes(ip, bytes)
        return InetSocketAddress(InetAddress.getByAddress(bytes), port)
    }

    private fun resolveProcNet(info: IpPacketInfo): Int {
        val file = when (info.protocol) {
            IpPacketParser.PROTO_TCP -> File("/proc/net/tcp")
            IpPacketParser.PROTO_UDP -> File("/proc/net/udp")
            else -> return Process.INVALID_UID
        }
        if (!file.canRead()) return Process.INVALID_UID
        val remoteHex = ipv4PortHex(info.dstIpInt, info.dstPort)
        val localHex = ipv4PortHex(info.srcIpInt, info.srcPort)
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

    private fun ipv4PortHex(ip: Int, port: Int): String {
        val ipHex = String.format(
            "%02X%02X%02X%02X",
            ip and 0xff,
            (ip ushr 8) and 0xff,
            (ip ushr 16) and 0xff,
            (ip ushr 24) and 0xff,
        )
        val portHex = String.format("%04X", port)
        return "$ipHex:$portHex"
    }

    private class AddressScratch {
        val localBytes = ByteArray(4)
        val remoteBytes = ByteArray(4)
    }

    companion object {
        private val addressScratch = ThreadLocal.withInitial { AddressScratch() }
        private const val PAC_UID_RETRY = 5
        private const val PAC_UID_SLEEP_MS = 4L

        fun isValidUid(uid: Int): Boolean =
            uid != Process.INVALID_UID && uid >= 0
    }
}
