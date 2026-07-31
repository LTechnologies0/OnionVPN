package ltechnologies.onionphone.onionvpn.core.vpn.profile

import android.os.ParcelFileDescriptor

/**
 * TUN packet engine (UID SOCKS or hev) started after the VPN interface is up.
 *
 * @param torDnsPort Tor DNSPort for AutomapHostsOnResolve (`.onion` / `.exit` only).
 *   Clearnet DNS stays on DNSCrypt; `0` disables Automap divert.
 * @param synthesizeOnionAutomap when true (Arti), answer `.onion`/`.exit` locally
 *   instead of querying Tor DNSPort.
 */
interface TunForwarder {
    fun start(
        tunFd: ParcelFileDescriptor,
        socksHost: String,
        socksPort: Int,
        dnsCryptPort: Int,
        torDnsPort: Int = 0,
        synthesizeOnionAutomap: Boolean = false,
    )

    fun stop()
}
