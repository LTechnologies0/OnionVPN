package ltechnologies.onionphone.onionvpn.core.validation.path

import java.net.InetAddress
import okhttp3.Dns

/**
 * OkHttp DNS that never resolves on the clearnet.
 *
 * Tor SOCKS5 with hostname CONNECT (SOCKS5h) needs an unresolved name. Using
 * [Dns.SYSTEM] while OnionVPN is [VpnService.Builder.addDisallowedApplication]
 * would leak A/AAAA queries on the underlying Wi‑Fi/cellular (Privacy Guides /
 * Tor threat model: excluded UID clearnet DNS).
 *
 * Returns a placeholder [InetAddress] whose hostname is the original name so
 * OkHttp's SOCKS layer sends the hostname to Tor for remote resolution.
 */
object TorSocksDns : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        // getByAddress(hostname, addr) keeps hostname for SOCKS5 unresolved CONNECT.
        val placeholder = InetAddress.getByAddress(hostname, byteArrayOf(0, 0, 0, 0))
        return listOf(placeholder)
    }
}
