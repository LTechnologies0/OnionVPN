package ltechnologies.onionphone.onionvpn.core.vpn.onionmasq

import android.content.Context
import android.content.pm.PackageManager
import timber.log.Timber

/**
 * Packages that already speak Tor — exclude from onionmasq UID routing (clearnet via protect)
 * to avoid Tor-over-Tor.
 */
object TorNativeAppUids {
    /**
     * Orbot [BYPASS_VPN_PACKAGES] + Tor VPN Tor-powered set + OnionVPN extras.
     * Package-name match only (no signature pinning yet — Tor VPN AppManager does pin).
     */
    private val PACKAGES = listOf(
        "org.briarproject.briar.android",
        "org.briarproject.mailbox",
        "org.onionshare.android",
        "org.onionshare.android.fdroid",
        "org.onionshare.android.nightly",
        "org.torproject.android",
        "org.torproject.android.nightly",
        "org.torproject.torbrowser",
        "org.torproject.torbrowser_alpha",
        "org.torproject.torbrowser_debug",
        "org.torproject.torbrowser_nightly",
        "org.torproject.torservices",
        "org.torproject.vpn",
        "im.cwtch.flwtch", // Orbot BYPASS_VPN_PACKAGES — Tor-over-Tor
    )

    fun resolve(context: Context): LongArray {
        val pm = context.packageManager
        val uids = ArrayList<Long>()
        for (pkg in PACKAGES) {
            try {
                uids.add(pm.getPackageUid(pkg, 0).toLong())
            } catch (_: PackageManager.NameNotFoundException) {
                // not installed
            }
        }
        Timber.d("Tor-native UIDs for onionmasq exclude: %s", uids)
        return uids.toLongArray()
    }
}
