package ltechnologies.onionphone.onionvpn.core.vpn.profile

import android.content.pm.PackageManager
import android.os.Process
import timber.log.Timber

/**
 * Optional clearnet leak for wireless ADB (`adbd` / [SHELL_PACKAGE]).
 *
 * **Default is fail-closed**: shell stays on the VPN (or offline under lockdown) —
 * never call [disallowPackages] / [extraExcludedUids] unless the user explicitly
 * enables [ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences.allowAdbClearnetLeak].
 *
 * USB ADB does not use the IP stack and is unaffected either way.
 */
object AdbVpnBypass {
    /** Package that owns wireless `adbd` on stock / AOSP builds. */
    const val SHELL_PACKAGE = "com.android.shell"

    /**
     * Packages to [android.net.VpnService.Builder.addDisallowedApplication] when
     * ADB clearnet leak is opted in. Empty when the shell package is missing.
     */
    fun disallowPackages(pm: PackageManager): List<String> {
        return if (isPackageInstalled(pm, SHELL_PACKAGE)) {
            listOf(SHELL_PACKAGE)
        } else {
            Timber.w("ADB clearnet leak requested but %s not installed", SHELL_PACKAGE)
            emptyList()
        }
    }

    /**
     * Extra UIDs for onionmasq [org.torproject.onionmasq.OnionMasq.setExcludedUids]
     * when ADB clearnet leak is opted in (shell UID + package UID if distinct).
     */
    fun extraExcludedUids(pm: PackageManager): LongArray {
        val uids = LinkedHashSet<Long>()
        uids.add(Process.SHELL_UID.toLong())
        runCatching {
            uids.add(pm.getPackageUid(SHELL_PACKAGE, 0).toLong())
        }.onFailure {
            Timber.d(it, "shell package UID unavailable for ADB exclude")
        }
        return uids.toLongArray()
    }

    private fun isPackageInstalled(pm: PackageManager, packageName: String): Boolean {
        return try {
            pm.getPackageInfo(packageName, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }
}
