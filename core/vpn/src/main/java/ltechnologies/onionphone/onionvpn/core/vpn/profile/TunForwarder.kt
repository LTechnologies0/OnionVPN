package ltechnologies.onionphone.onionvpn.core.vpn.profile

import android.os.ParcelFileDescriptor

/**
 * TUN packet forwarder (hev-socks5-tunnel implementation in `forwarder/`).
 *
 * Owned by [ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService] while Connected.
 */
interface TunForwarder {
    fun start(tunFd: ParcelFileDescriptor, socksHost: String, socksPort: Int, dnsCryptPort: Int)
    fun stop()
}
