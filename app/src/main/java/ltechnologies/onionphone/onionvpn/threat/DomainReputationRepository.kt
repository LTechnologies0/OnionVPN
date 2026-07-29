package ltechnologies.onionphone.onionvpn.threat

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.model.DomainThreatCategory
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager
import ltechnologies.onionphone.onionvpn.core.validation.path.TorSocksDns
import okhttp3.OkHttpClient
import okhttp3.Request
import timber.log.Timber

/**
 * Downloads and refreshes HaGeZi DNS blocklists used to colour firewall prompts:
 *
 * - **Malware / C2 (red):** HaGeZi Threat Intelligence Feeds (TIF) mini
 * - **Ads / tracking / telemetry (orange):** HaGeZi Light + Native Tracker lists
 *
 * Prefer Tor probe SOCKS when the tunnel is up. Never downloads over clearnet
 * (excluded-UID OkHttp would leak DNS + SNI on the ISP path — Privacy Guides /
 * Tor threat model). Seed lists via cache until [onTorReady].
 */
@Singleton
class DomainReputationRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val tor: TorProcessManager,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val index = DomainReputationIndex()
    private val updateMutex = Mutex()
    private val started = AtomicBoolean(false)

    private val _status = MutableStateFlow(DomainReputationStatus())
    val status: StateFlow<DomainReputationStatus> = _status.asStateFlow()

    fun classify(hostname: String?): DomainThreatCategory = index.classify(hostname)

    fun start() {
        if (!started.compareAndSet(false, true)) return
        scope.launch {
            loadCached()
            maybeAutoUpdate()
        }
    }

    /** Force a refresh (Settings button / post-Tor-ready hook). */
    fun requestUpdate() {
        scope.launch { update() }
    }

    /**
     * Prefer a Tor-backed refresh when probe SOCKS appears.
     * If the last success was clearnet (or never via Tor), refresh immediately.
     */
    fun onTorReady() {
        scope.launch {
            val st = _status.value
            if (!st.lastViaTor) {
                update()
            } else {
                maybeAutoUpdate()
            }
        }
    }

    private suspend fun maybeAutoUpdate() {
        val st = _status.value
        val age = System.currentTimeMillis() - st.lastSuccessEpochMs
        if (st.lastSuccessEpochMs > 0L && age < REFRESH_INTERVAL_MS) return
        update()
    }

    private suspend fun loadCached() = withContext(Dispatchers.IO) {
        val dir = listDir()
        val malwareOk = index.loadMalwareFrom(File(dir, MALWARE_FILE))
        val trackingOk = index.loadTrackingFrom(File(dir, TRACKING_FILE))
        val meta = File(dir, META_FILE)
        val lastSuccess = meta.takeIf { it.isFile }?.readText()?.toLongOrNull() ?: 0L
        val lastViaTor = File(dir, VIA_TOR_FILE).takeIf { it.isFile }
            ?.readText()?.trim() == "1"
        _status.value = DomainReputationStatus(
            malwareEntries = index.malwareCount(),
            trackingEntries = index.trackingCount(),
            lastSuccessEpochMs = lastSuccess,
            lastError = null,
            updating = false,
            loadedFromCache = malwareOk || trackingOk,
            lastViaTor = lastViaTor,
        )
    }

    private suspend fun update() {
        updateMutex.withLock {
            if (_status.value.updating) return@withLock
            _status.value = _status.value.copy(updating = true, lastError = null)
            val result = runCatching {
                withContext(Dispatchers.IO) { downloadAndSwap() }
            }
            result.onSuccess { viaTor ->
                val now = System.currentTimeMillis()
                val dir = listDir()
                File(dir, META_FILE).writeText(now.toString())
                File(dir, VIA_TOR_FILE).writeText(if (viaTor) "1" else "0")
                _status.value = DomainReputationStatus(
                    malwareEntries = index.malwareCount(),
                    trackingEntries = index.trackingCount(),
                    lastSuccessEpochMs = now,
                    lastError = null,
                    updating = false,
                    loadedFromCache = true,
                    lastViaTor = viaTor,
                )
                Timber.i(
                    "Domain reputation updated malware=%d tracking=%d viaTor=%s",
                    index.malwareCount(),
                    index.trackingCount(),
                    viaTor,
                )
            }.onFailure { error ->
                Timber.w(error, "Domain reputation update failed")
                _status.value = _status.value.copy(
                    updating = false,
                    lastError = error.message ?: "update failed",
                )
            }
        }
    }

    /** @return true when the download used Tor probe SOCKS. */
    private fun downloadAndSwap(): Boolean {
        val dir = listDir()
        val transport = buildClient()
        val client = transport.client
        try {
            val malwareTmp = File(dir, "$MALWARE_FILE.tmp")
            val trackingTmp = File(dir, "$TRACKING_FILE.tmp")

            downloadFirstAvailable(client, MALWARE_URLS, malwareTmp)
            // Tracking = Light (ads/tracking/metrics) + Native OEM telemetry lists.
            trackingTmp.bufferedWriter(Charsets.UTF_8).use { out ->
                out.appendLine("# OnionVPN merged tracking/telemetry list")
                out.appendLine("# Base: HaGeZi Light + Native Tracker")
                val light = downloadBodyFirstAvailable(client, TRACKING_LIGHT_URLS)
                out.appendLine("# source: HaGeZi Light")
                out.append(light)
                if (!light.endsWith('\n')) out.appendLine()
                for (url in TRACKING_NATIVE_URLS) {
                    try {
                        val body = fetchBody(client, url)
                        out.appendLine("# source: $url")
                        out.append(body)
                        if (!body.endsWith('\n')) out.appendLine()
                    } catch (error: Exception) {
                        Timber.d(error, "Optional native list skipped: %s", url)
                    }
                }
            }

            val malwareSet = HashSet<String>(180_000)
            malwareTmp.bufferedReader(Charsets.UTF_8).use {
                DomainReputationIndex.parseDomains(it, malwareSet)
            }
            val trackingSet = HashSet<String>(64_000)
            trackingTmp.bufferedReader(Charsets.UTF_8).use {
                DomainReputationIndex.parseDomains(it, trackingSet)
            }
            if (malwareSet.isEmpty() && trackingSet.isEmpty()) {
                throw IllegalStateException("Downloaded domain lists were empty")
            }

            val malwareFinal = File(dir, MALWARE_FILE)
            val trackingFinal = File(dir, TRACKING_FILE)
            if (!malwareTmp.renameTo(malwareFinal)) {
                malwareTmp.copyTo(malwareFinal, overwrite = true)
                malwareTmp.delete()
            }
            if (!trackingTmp.renameTo(trackingFinal)) {
                trackingTmp.copyTo(trackingFinal, overwrite = true)
                trackingTmp.delete()
            }

            if (malwareSet.isNotEmpty()) index.replaceMalware(malwareSet)
            if (trackingSet.isNotEmpty()) index.replaceTracking(trackingSet)
            return transport.viaTor
        } finally {
            client.dispatcher.executorService.shutdown()
            client.connectionPool.evictAll()
        }
    }

    private fun downloadFirstAvailable(client: OkHttpClient, urls: List<String>, dest: File) {
        dest.writeText(downloadBodyFirstAvailable(client, urls), Charsets.UTF_8)
    }

    private fun downloadBodyFirstAvailable(client: OkHttpClient, urls: List<String>): String {
        var lastError: Exception? = null
        for (url in urls) {
            try {
                val body = fetchBody(client, url)
                if (body.isNotBlank()) return body
            } catch (error: Exception) {
                lastError = error
                Timber.d(error, "Blocklist mirror failed: %s", url)
            }
        }
        throw lastError ?: IllegalStateException("No blocklist mirrors configured")
    }

    private fun fetchBody(client: OkHttpClient, url: String): String {
        val response = client.newCall(
            Request.Builder()
                .url(url)
                .header("User-Agent", "OnionVPN-DomainReputation/1.0")
                .header("Accept", "text/plain")
                .build(),
        ).execute()
        return response.use {
            if (!it.isSuccessful) {
                throw IllegalStateException("HTTP ${it.code} for $url")
            }
            it.body?.string().orEmpty()
        }
    }

    private data class HttpTransport(val client: OkHttpClient, val viaTor: Boolean)

    private fun buildClient(): HttpTransport {
        val probePort = tor.currentProbeSocksPort()
        if (probePort == null || !tor.isRunning()) {
            Timber.i("Domain reputation: Tor probe SOCKS unavailable — cache only (no clearnet)")
            throw IllegalStateException("Tor probe SOCKS not ready — refusing clearnet download")
        }
        val proxy = Proxy(
            Proxy.Type.SOCKS,
            InetSocketAddress(TunnelEndpoints.LOOPBACK, probePort),
        )
        val client = OkHttpClient.Builder()
            .proxy(proxy)
            .dns(TorSocksDns)
            .connectTimeout(60, TimeUnit.SECONDS)
            .readTimeout(120, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)
            .followRedirects(true)
            .followSslRedirects(true)
            .build()
        Timber.i("Domain reputation download via Tor probe SOCKS :%d", probePort)
        return HttpTransport(client, viaTor = true)
    }

    private fun listDir(): File =
        File(context.filesDir, "domain-reputation").also { it.mkdirs() }

    companion object {
        private const val MALWARE_FILE = "hagezi-tif-mini.txt"
        private const val TRACKING_FILE = "hagezi-tracking.txt"
        private const val META_FILE = "last-success.txt"
        private const val VIA_TOR_FILE = "last-via-tor.txt"
        /** HaGeZi lists expire ~12h–1d; refresh daily. */
        private const val REFRESH_INTERVAL_MS = 24L * 60L * 60L * 1000L

        private val MALWARE_URLS = listOf(
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
            "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/tif.mini-onlydomains.txt",
        )

        private val TRACKING_LIGHT_URLS = listOf(
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
            "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/light-onlydomains.txt",
        )

        private val TRACKING_NATIVE_URLS = listOf(
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.apple-onlydomains.txt",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.amazon-onlydomains.txt",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.huawei-onlydomains.txt",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.samsung-onlydomains.txt",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.xiaomi-onlydomains.txt",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.oppo-realme-onlydomains.txt",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.vivo-onlydomains.txt",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.winoffice-onlydomains.txt",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.tiktok-onlydomains.txt",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.roku-onlydomains.txt",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.lgwebos-onlydomains.txt",
        )
    }
}

data class DomainReputationStatus(
    val malwareEntries: Int = 0,
    val trackingEntries: Int = 0,
    val lastSuccessEpochMs: Long = 0L,
    val lastError: String? = null,
    val updating: Boolean = false,
    val loadedFromCache: Boolean = false,
    /** True when the last successful download used Tor probe SOCKS. */
    val lastViaTor: Boolean = false,
)
