package ltechnologies.onionphone.onionvpn.core.vpn.onionmasq

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest
import timber.log.Timber

/**
 * Packages that already speak Tor — exclude from VPN routing (hev) and onionmasq UID
 * routing (clearnet via protect) to avoid Tor-over-Tor.
 *
 * Dual layer:
 * - hev / all planes: [VpnService.Builder.addDisallowedApplication] via VpnProfileBuilder
 * - onionmasq: [OnionMasq.setExcludedUids] before start
 *
 * **Signature pinning** (Tor VPN AppManager model): package name alone is not enough —
 * a typosquat with the same name would get clearnet BYPASS. Only packages whose signing
 * certificate SHA-256 matches a known publisher pin are treated as Tor-native.
 */
object TorNativeAppUids {
    /**
     * Orbot [BYPASS_VPN_PACKAGES] + Tor VPN Tor-powered set + OnionVPN extras.
     * Candidate names only — [resolve] / [installedBypassPackages] require pin match.
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

    /** Orbot core BYPASS set — must remain a subset of [bypassPackages]. */
    val ORBOT_BYPASS_PACKAGES: Set<String> = setOf(
        "org.briarproject.briar.android",
        "org.briarproject.mailbox",
        "org.onionshare.android",
        "org.torproject.torbrowser",
        "org.torproject.torbrowser_alpha",
        "im.cwtch.flwtch",
    )

    // Certificate SHA-256 digests (lowercase hex) from Tor Browser signing scripts /
    // Pithus / PrivacyGuides verified fingerprints. Fail-closed when none match.
    private const val CERT_TOR_PROJECT_LEGACY =
        "a454b87a1847a89ed7f5e70fba6bba96f3ef29c26e0981204fe347bf231dfd5b"
    private const val CERT_TBB_RELEASE =
        "20061f045e737c67375c17794cfedb436a03cec6bacb7cb9f96642205ca2cec8"
    private const val CERT_TBB_ALPHA =
        "15f760b41acbe4783e667102c9f67119be2af62fab07763f9d57f01e5e1074e1"
    private const val CERT_TOR_VPN =
        "c2f6ffa30e56a7c53a226248ef908612ee539df2f52bede5a55037425b83331d"
    private const val CERT_BRIAR =
        "501ddf14a6ecf904fb20285c56a565cb987a867f91572ee33c2d43771cca4e37"
    /** F-Droid primary signing key — official F-Droid builds of pinned packages. */
    private const val CERT_FDROID =
        "43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab"

    /**
     * Allowed signing-cert digests per package. Empty set = never bypass (no pin known).
     * Multiple pins cover release / alpha / F-Droid channels.
     */
    private val PINNED_CERT_SHA256: Map<String, Set<String>> = mapOf(
        "org.torproject.android" to setOf(CERT_TOR_PROJECT_LEGACY, CERT_FDROID),
        "org.torproject.android.nightly" to setOf(CERT_TOR_PROJECT_LEGACY, CERT_FDROID),
        "org.torproject.torservices" to setOf(CERT_TOR_PROJECT_LEGACY, CERT_FDROID),
        "org.torproject.torbrowser" to setOf(CERT_TBB_RELEASE, CERT_FDROID),
        "org.torproject.torbrowser_alpha" to setOf(CERT_TBB_ALPHA, CERT_FDROID),
        // Debug/nightly often use local/dev keys — pin release/alpha only if remapped.
        "org.torproject.torbrowser_debug" to setOf(CERT_TBB_ALPHA, CERT_TBB_RELEASE),
        "org.torproject.torbrowser_nightly" to setOf(CERT_TBB_ALPHA, CERT_TBB_RELEASE),
        "org.torproject.vpn" to setOf(CERT_TOR_VPN, CERT_FDROID),
        "org.briarproject.briar.android" to setOf(CERT_BRIAR, CERT_FDROID),
        "org.briarproject.mailbox" to setOf(CERT_BRIAR, CERT_FDROID),
        // OnionShare / Cwtch: F-Droid channel only until vendor pin is published in-tree.
        "org.onionshare.android" to setOf(CERT_FDROID),
        "org.onionshare.android.fdroid" to setOf(CERT_FDROID),
        "org.onionshare.android.nightly" to setOf(CERT_FDROID),
        "im.cwtch.flwtch" to setOf(CERT_FDROID),
    )

    /** Package names that must never be Tor-over-Tor through OnionVPN (name list). */
    fun bypassPackages(): List<String> = PACKAGES

    fun isBypassPackage(packageName: String): Boolean = packageName in PACKAGES

    /** True when [packageName] is installed and signing cert matches a known pin. */
    fun isPinnedBypassInstalled(context: Context, packageName: String): Boolean {
        if (!isBypassPackage(packageName)) return false
        return matchesPinnedSignature(context.packageManager, packageName)
    }

    fun resolve(context: Context): LongArray {
        val pm = context.packageManager
        val uids = ArrayList<Long>()
        for (pkg in PACKAGES) {
            if (!matchesPinnedSignature(pm, pkg)) continue
            try {
                uids.add(pm.getPackageUid(pkg, 0).toLong())
            } catch (_: PackageManager.NameNotFoundException) {
                // not installed
            }
        }
        Timber.d("Tor-native UIDs for onionmasq exclude (pinned): %s", uids)
        return uids.toLongArray()
    }

    /** Installed + **pinned** BYPASS packages for VpnService.Builder.addDisallowedApplication. */
    fun installedBypassPackages(context: Context): List<String> {
        val pm = context.packageManager
        return PACKAGES.filter { pkg -> matchesPinnedSignature(pm, pkg) }
    }

    /**
     * True when [packageName] from a PACKAGE_* intent is a Tor-native candidate
     * (name match). Callers rebind / refresh regardless of pin so a pin-pass install
     * and a pin-fail uninstall both update routing.
     */
    fun isBypassPackageFromUri(packageUri: String?): Boolean {
        if (packageUri.isNullOrBlank()) return false
        val pkg = packageUri.removePrefix("package:")
        return isBypassPackage(pkg)
    }

    internal fun matchesPinnedSignature(pm: PackageManager, packageName: String): Boolean {
        val pins = PINNED_CERT_SHA256[packageName]
        if (pins.isNullOrEmpty()) {
            Timber.w("Tor-native BYPASS denied — no pin configured for %s", packageName)
            return false
        }
        val digests = runCatching { signingCertSha256Hex(pm, packageName) }
            .onFailure { Timber.w(it, "signing cert read failed for %s", packageName) }
            .getOrNull()
            ?: return false
        if (digests.isEmpty()) return false
        val ok = digests.any { it in pins }
        if (!ok) {
            Timber.w(
                "Tor-native BYPASS denied — signature mismatch for %s digests=%s",
                packageName,
                digests,
            )
        }
        return ok
    }

    private fun signingCertSha256Hex(pm: PackageManager, packageName: String): Set<String> {
        val info = packageInfoForSigning(pm, packageName) ?: return emptySet()
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = info.signingInfo ?: return emptySet()
            if (signingInfo.hasMultipleSigners()) {
                signingInfo.apkContentsSigners
            } else {
                signingInfo.signingCertificateHistory
            }
        } else {
            @Suppress("DEPRECATION")
            info.signatures
        }
        if (signatures.isNullOrEmpty()) return emptySet()
        val md = MessageDigest.getInstance("SHA-256")
        return signatures.mapTo(LinkedHashSet()) { sig ->
            md.reset()
            md.digest(sig.toByteArray()).joinToString("") { b -> "%02x".format(b) }
        }
    }

    private fun packageInfoForSigning(pm: PackageManager, packageName: String): PackageInfo? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
            }
        } catch (_: PackageManager.NameNotFoundException) {
            null
        }
    }
}
