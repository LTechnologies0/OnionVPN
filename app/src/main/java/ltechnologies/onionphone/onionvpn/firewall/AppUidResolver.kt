package ltechnologies.onionphone.onionvpn.firewall

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Build
import android.os.Process
import androidx.core.content.ContextCompat
import java.util.concurrent.ConcurrentHashMap
import timber.log.Timber

/**
 * Maps Linux UIDs → human package/label for the interactive firewall.
 *
 * Pattern used by NetGuard / RethinkDNS / OpenSnitch-on-Android:
 * 1. Well-known system UIDs (root, system, mediaserver, nobody, …)
 * 2. [PackageManager.getPackagesForUid] (needs [android.Manifest.permission.QUERY_ALL_PACKAGES]
 *    on API 30+ — already declared)
 * 3. Reverse index from [PackageManager.getInstalledApplications] (covers visibility edge cases)
 * 4. [PackageManager.getNameForUid] sharedUserId / isolated fallback
 *
 * Negative lookups are **not** cached permanently so a later package-install or visibility
 * refresh can recover a real name.
 */
class AppUidResolver(
    private val context: Context,
) {
    data class Identity(
        val packageName: String,
        val label: String,
        /** True when we have a real package or well-known system name. */
        val confident: Boolean,
        val allPackages: List<String> = listOf(packageName),
    )

    private val appContext = context.applicationContext
    private val pm = appContext.packageManager

    /** Successful UID → identity only. */
    private val cache = ConcurrentHashMap<Int, Identity>()

    /** appId (uid % PER_USER) → packages — refreshed on package broadcasts. */
    private val uidIndex = ConcurrentHashMap<Int, List<String>>()

    @Volatile private var receiverRegistered = false

    private val packageReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context?, intent: Intent?) {
            refreshIndex()
            cache.clear()
        }
    }

    fun start() {
        if (receiverRegistered) return
        refreshIndex()
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addAction(Intent.ACTION_PACKAGE_CHANGED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        ContextCompat.registerReceiver(
            appContext,
            packageReceiver,
            filter,
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        receiverRegistered = true
    }

    fun stop() {
        if (!receiverRegistered) return
        runCatching { appContext.unregisterReceiver(packageReceiver) }
        receiverRegistered = false
    }

    fun resolve(uid: Int): Identity {
        if (uid == Process.INVALID_UID || uid < 0) {
            return Identity("unknown", "Unresolved app", confident = false)
        }
        cache[uid]?.let { return it }

        wellKnown(uid)?.let {
            cache[uid] = it
            return it
        }

        val packages = packagesForUid(uid)
        if (packages.isNotEmpty()) {
            val primary = pickPrimary(packages)
            val labels = packages.mapNotNull { pkgLabel(it) }.distinct()
            val label = when {
                labels.isEmpty() -> primary
                labels.size == 1 -> labels.first()
                else -> labels.joinToString(", ")
            }
            val id = Identity(
                packageName = primary,
                label = label,
                confident = true,
                allPackages = packages,
            )
            cache[uid] = id
            trimCache()
            return id
        }

        // sharedUserId string e.g. "android.uid.system:1000"
        val nameForUid = runCatching { pm.getNameForUid(uid) }.getOrNull()
        if (!nameForUid.isNullOrBlank()) {
            val shared = nameForUid.substringBefore(':')
            val label = when {
                shared.startsWith("android.uid.") ->
                    shared.removePrefix("android.uid.").replaceFirstChar { it.uppercase() } +
                        " (UID $uid)"
                else -> {
                    pkgLabel(shared) ?: shared
                }
            }
            val id = Identity(
                packageName = shared,
                label = label,
                confident = true,
                allPackages = listOf(shared),
            )
            cache[uid] = id
            trimCache()
            return id
        }

        // Soft miss — do not cache.
        val appId = uid % PER_USER_RANGE
        val user = uid / PER_USER_RANGE
        val hint = if (user > 0) "u$user/" else ""
        return Identity(
            packageName = "uid:$uid",
            label = "App $hint#$appId (UID $uid)",
            confident = false,
        )
    }

    fun refreshIndex() {
        try {
            val flags = PackageManager.MATCH_UNINSTALLED_PACKAGES or
                PackageManager.MATCH_DISABLED_COMPONENTS
            @Suppress("DEPRECATION")
            val apps = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledApplications(
                    PackageManager.ApplicationInfoFlags.of(flags.toLong()),
                )
            } else {
                pm.getInstalledApplications(flags)
            }
            val grouped = apps.groupBy { it.uid }.mapValues { (_, list) ->
                list.map { it.packageName }.distinct()
            }
            uidIndex.clear()
            uidIndex.putAll(grouped)
            Timber.i("AppUidResolver indexed ${grouped.size} UIDs / ${apps.size} packages")
        } catch (error: Exception) {
            Timber.w(error, "AppUidResolver index refresh failed")
        }
    }

    private fun packagesForUid(uid: Int): List<String> {
        val fromPm = runCatching { pm.getPackagesForUid(uid) }.getOrNull()
            ?.filter { it.isNotBlank() }
            .orEmpty()
        if (fromPm.isNotEmpty()) return fromPm.distinct()

        uidIndex[uid]?.takeIf { it.isNotEmpty() }?.let { return it }

        // Multi-user: index keys are full UIDs from getInstalledApplications.
        // Also try appId within current user if caller passed a related uid.
        val appId = uid % PER_USER_RANGE
        return uidIndex.entries
            .filter { (key, _) -> key % PER_USER_RANGE == appId }
            .flatMap { it.value }
            .distinct()
    }

    private fun pickPrimary(packages: List<String>): String {
        if (packages.size == 1) return packages.first()
        val withLauncher = packages.filter { hasLauncher(it) }
        val candidates = withLauncher.ifEmpty { packages }
        // Prefer user (non-system) apps when several share a UID.
        val userApps = candidates.filter { pkg ->
            runCatching {
                val ai = applicationInfo(pkg) ?: return@runCatching false
                ai.flags and ApplicationInfo.FLAG_SYSTEM == 0
            }.getOrDefault(false)
        }
        return (userApps.ifEmpty { candidates }).minByOrNull { it.length } ?: packages.first()
    }

    private fun hasLauncher(pkg: String): Boolean {
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER).setPackage(pkg)
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.queryIntentActivities(
                    intent,
                    PackageManager.ResolveInfoFlags.of(0),
                ).isNotEmpty()
            } else {
                @Suppress("DEPRECATION")
                pm.queryIntentActivities(intent, 0).isNotEmpty()
            }
        }.getOrDefault(false)
    }

    private fun pkgLabel(pkg: String): String? = try {
        val ai = applicationInfo(pkg) ?: return null
        pm.getApplicationLabel(ai).toString().ifBlank { null }
    } catch (_: Exception) {
        null
    }

    /** App icon for circuit / firewall cards; null when package unknown. */
    fun iconDrawable(uid: Int): Drawable? {
        val id = resolve(uid)
        if (!id.confident || id.packageName.startsWith("android.uid.")) return null
        return runCatching { pm.getApplicationIcon(id.packageName) }.getOrNull()
    }

    private fun applicationInfo(pkg: String): ApplicationInfo? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getApplicationInfo(pkg, 0)
        }
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }

    private fun wellKnown(uid: Int): Identity? {
        val appId = uid % PER_USER_RANGE
        val label = when (appId) {
            Process.ROOT_UID -> "Root"
            Process.SYSTEM_UID -> "Android System"
            Process.PHONE_UID -> "Phone"
            Process.SHELL_UID -> "Shell"
            1010 -> "Wi‑Fi"
            1013 -> "Media server"
            1016 -> "Network stack"
            1051 -> "Network stack (netd)"
            9999 -> "Nobody"
            in FIRST_ISOLATED_UID..LAST_ISOLATED_UID -> "Isolated process"
            else -> return null
        }
        // Only treat as well-known when getPackagesForUid is empty — otherwise prefer real pkgs.
        val pkgs = runCatching { pm.getPackagesForUid(uid) }.getOrNull().orEmpty()
        if (pkgs.isNotEmpty() && appId >= Process.FIRST_APPLICATION_UID) return null
        if (pkgs.isNotEmpty() && appId < Process.FIRST_APPLICATION_UID) {
            val names = pkgs.mapNotNull { pkgLabel(it) }.ifEmpty { listOf(label) }
            return Identity(
                packageName = pkgs.first(),
                label = names.joinToString(", "),
                confident = true,
                allPackages = pkgs.toList(),
            )
        }
        return Identity(
            packageName = "android.uid.$appId",
            label = "$label (UID $uid)",
            confident = true,
        )
    }

    private fun trimCache() {
        if (cache.size <= MAX_CACHE) return
        var n = 0
        val it = cache.keys.iterator()
        while (it.hasNext() && n < MAX_CACHE / 2) {
            it.next()
            it.remove()
            n++
        }
    }

    companion object {
        private const val PER_USER_RANGE = 100_000
        private const val FIRST_ISOLATED_UID = 99000
        private const val LAST_ISOLATED_UID = 99999
        private const val MAX_CACHE = 512
    }
}
