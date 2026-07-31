package ltechnologies.onionphone.onionvpn.threat.repo

import ltechnologies.onionphone.onionvpn.threat.catalog.DomainBlocklistCatalog
import ltechnologies.onionphone.onionvpn.threat.index.DomainReputationIndex
import ltechnologies.onionphone.onionvpn.threat.parse.DomainListParser
import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.model.DomainThreatCategory
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager
import ltechnologies.onionphone.onionvpn.core.validation.path.TorSocksDns
import okhttp3.Call
import okhttp3.OkHttpClient
import okhttp3.Request
import timber.log.Timber
import kotlin.coroutines.coroutineContext

/**
 * Maintains a **local unified domain reputation DB** under `files/domain-reputation/`:
 *
 * - `malware.txt` / `tracking.txt` — merged, one domain per line (runtime lookup)
 * - `sources/{id}.txt` — raw cache per [DomainBlocklistCatalog] feed
 *
 * Feeds (HaGeZi, URLhaus, Yoyo adservers, uAssets, …) are fetched over Tor probe
 * SOCKS only — never clearnet. Classification colours firewall prompts.
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
    private val updateJob = AtomicReference<Job?>(null)
    private val activeCall = AtomicReference<Call?>(null)
    private val cachedHttpClient = AtomicReference<Pair<Int, OkHttpClient>?>(null)

    private val _status = MutableStateFlow(DomainReputationStatus())
    val status: StateFlow<DomainReputationStatus> = _status.asStateFlow()

    fun classify(hostname: String?): DomainThreatCategory = index.classify(hostname)

    fun start() {
        if (!started.compareAndSet(false, true)) return
        scope.launch {
            migrateLegacyFilenames()
            loadCached()
        }
    }

    fun requestUpdate() {
        launchUpdate { update() }
    }

    fun onTorReady() {
        launchUpdate {
            if (!awaitProbeSocks()) {
                Timber.w("Domain reputation: Tor probe SOCKS never became ready — keeping cache")
                return@launchUpdate
            }
            val st = _status.value
            val age = System.currentTimeMillis() - st.lastSuccessEpochMs
            if (st.lastViaTor && st.lastSuccessEpochMs > 0L && age < REFRESH_INTERVAL_MS) {
                Timber.d("Domain reputation fresh via Tor — skip auto-update")
                return@launchUpdate
            }
            if (!st.lastViaTor) {
                update()
            } else {
                maybeAutoUpdate()
            }
        }
    }

    /** Cancel in-flight Tor downloads when the tunnel leaves Connected / probe SOCKS dies. */
    fun onTorUnavailable() {
        updateJob.getAndSet(null)?.cancel()
        activeCall.getAndSet(null)?.cancel()
        if (_status.value.updating) {
            _status.value = _status.value.copy(
                updating = false,
                lastError = "Tor probe SOCKS unavailable — update aborted",
            )
            Timber.i("Domain reputation: aborted download (Tor SOCKS gone)")
        }
    }

    private fun launchUpdate(block: suspend () -> Unit) {
        updateJob.getAndSet(null)?.cancel()
        val job = scope.launch { block() }
        updateJob.set(job)
        job.invokeOnCompletion { updateJob.compareAndSet(job, null) }
    }

    private suspend fun awaitProbeSocks(
        attempts: Int = PROBE_WAIT_ATTEMPTS,
        delayMs: Long = PROBE_WAIT_DELAY_MS,
    ): Boolean {
        repeat(attempts) {
            if (tor.currentProbeSocksPort() != null && tor.isRunning()) return true
            delay(delayMs)
        }
        return tor.currentProbeSocksPort() != null && tor.isRunning()
    }

    private suspend fun maybeAutoUpdate() {
        val st = _status.value
        val age = System.currentTimeMillis() - st.lastSuccessEpochMs
        if (st.lastSuccessEpochMs > 0L && age < REFRESH_INTERVAL_MS) return
        update()
    }

    private suspend fun loadCached() = withContext(Dispatchers.IO) {
        val dir = listDir()
        val malwareOk = index.loadMalwareFrom(File(dir, MALWARE_DB))
        val trackingOk = index.loadTrackingFrom(File(dir, TRACKING_DB))
        val meta = File(dir, META_FILE)
        val lastSuccess = meta.takeIf { it.isFile }?.readText()?.toLongOrNull() ?: 0L
        val lastViaTor = File(dir, VIA_TOR_FILE).takeIf { it.isFile }
            ?.readText()?.trim() == "1"
        val sourcesOk = sourceCacheDir().listFiles()?.count { it.isFile && it.length() > 0L } ?: 0
        _status.value = DomainReputationStatus(
            malwareEntries = index.malwareCount(),
            trackingEntries = index.trackingCount(),
            sourceFilesCached = sourcesOk,
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
                withContext(Dispatchers.IO) { downloadMergeAndSwap() }
            }
            result.onSuccess { viaTor ->
                val now = System.currentTimeMillis()
                val dir = listDir()
                File(dir, META_FILE).writeText(now.toString())
                File(dir, VIA_TOR_FILE).writeText(if (viaTor) "1" else "0")
                val sourcesOk = sourceCacheDir().listFiles()?.count { it.isFile && it.length() > 0L } ?: 0
                _status.value = DomainReputationStatus(
                    malwareEntries = index.malwareCount(),
                    trackingEntries = index.trackingCount(),
                    sourceFilesCached = sourcesOk,
                    lastSuccessEpochMs = now,
                    lastError = null,
                    updating = false,
                    loadedFromCache = true,
                    lastViaTor = viaTor,
                )
                Timber.i(
                    "Domain reputation DB updated malware=%d tracking=%d sources=%d viaTor=%s",
                    index.malwareCount(),
                    index.trackingCount(),
                    sourcesOk,
                    viaTor,
                )
            }.onFailure { error ->
                val aborted = error.message?.contains("SOCKS", ignoreCase = true) == true ||
                    error.message?.contains("cancelled", ignoreCase = true) == true
                if (aborted) {
                    Timber.i("Domain reputation update aborted: %s", error.message)
                } else {
                    Timber.w(error, "Domain reputation update failed")
                }
                _status.value = _status.value.copy(
                    updating = false,
                    lastError = error.message ?: "update failed",
                )
            }
        }
    }

    /** @return true when the download used Tor probe SOCKS. */
    private suspend fun downloadMergeAndSwap(): Boolean {
        val transport = buildClient()
        val client = transport.client
        val expectedProbe = tor.currentProbeSocksPort()
        try {
            var requiredFailures = 0
            var fetched = 0
            for (source in DomainBlocklistCatalog.ALL) {
                if (!coroutineContext.isActive) {
                    throw IllegalStateException("Domain reputation update cancelled")
                }
                val liveProbe = tor.currentProbeSocksPort()
                if (liveProbe == null || !tor.isRunning() || liveProbe != expectedProbe) {
                    throw IllegalStateException("Tor probe SOCKS lost mid-update")
                }
                try {
                    val dest = sourceCacheFile(source.id)
                    val tmp = File(dest.absolutePath + ".tmp")
                    downloadToFile(client, source.urls, tmp)
                    if (!tmp.renameTo(dest)) {
                        tmp.copyTo(dest, overwrite = true)
                        tmp.delete()
                    }
                    fetched++
                    Timber.d("Domain source ok id=%s bytes=%d", source.id, dest.length())
                } catch (error: Exception) {
                    if (isProbeGone(error) || !tor.isRunning() || tor.currentProbeSocksPort() == null) {
                        Timber.i(
                            "Domain source aborted id=%s (Tor SOCKS gone): %s",
                            source.id,
                            error.message,
                        )
                        throw IllegalStateException("Tor probe SOCKS lost mid-update", error)
                    }
                    Timber.w(error, "Domain source failed id=%s required=%s", source.id, source.required)
                    if (source.required && !sourceCacheFile(source.id).isFile) {
                        requiredFailures++
                    }
                }
            }
            if (fetched == 0 && requiredFailures > 0) {
                throw IllegalStateException("No blocklist sources downloaded")
            }

            val malwareSet = HashSet<String>(200_000)
            val trackingSet = HashSet<String>(80_000)
            for (source in DomainBlocklistCatalog.ALL) {
                val cache = sourceCacheFile(source.id)
                if (!cache.isFile || cache.length() == 0L) continue
                cache.bufferedReader(Charsets.UTF_8).use { reader ->
                    DomainListParser.parse(reader, source.format, when (source.category) {
                        DomainThreatCategory.MALWARE -> malwareSet
                        DomainThreatCategory.TRACKING -> trackingSet
                        DomainThreatCategory.NONE -> trackingSet
                    })
                }
            }
            // Malware wins: drop tracking duplicates that are already malware (skip if sets huge).
            if (malwareSet.isNotEmpty() && malwareSet.size + trackingSet.size < MERGE_DEDUPE_MAX) {
                trackingSet.removeAll(malwareSet)
            }
            if (malwareSet.isEmpty() && trackingSet.isEmpty()) {
                throw IllegalStateException("Merged domain DB was empty")
            }

            writeUnifiedDb(MALWARE_DB, malwareSet, "malware")
            writeUnifiedDb(TRACKING_DB, trackingSet, "tracking")

            if (malwareSet.isNotEmpty()) index.replaceMalware(malwareSet)
            if (trackingSet.isNotEmpty()) index.replaceTracking(trackingSet)
            return transport.viaTor
        } finally {
            activeCall.getAndSet(null)?.cancel()
        }
    }

    private fun isProbeGone(error: Throwable): Boolean {
        val msg = error.message.orEmpty()
        return msg.contains("ECONNREFUSED", ignoreCase = true) ||
            msg.contains("Malformed reply from SOCKS", ignoreCase = true) ||
            msg.contains("Connection refused", ignoreCase = true) ||
            msg.contains("SOCKS lost", ignoreCase = true)
    }

    private fun writeUnifiedDb(name: String, domains: Set<String>, kind: String) {
        val dir = listDir()
        val final = File(dir, name)
        val tmp = File(dir, "$name.tmp")
        tmp.bufferedWriter(Charsets.UTF_8).use { out ->
            out.appendLine("# OnionVPN unified $kind domain DB")
            out.appendLine("# Merged from DomainBlocklistCatalog sources — do not edit")
            out.appendLine("# entries=${domains.size}")
            domains.forEach { out.appendLine(it) }
        }
        if (!tmp.renameTo(final)) {
            tmp.copyTo(final, overwrite = true)
            tmp.delete()
        }
    }

    private fun downloadToFile(client: OkHttpClient, urls: List<String>, dest: File) {
        var lastError: Exception? = null
        for (url in urls) {
            try {
                fetchBodyToFile(client, url, dest)
                if (dest.length() > 0L) return
            } catch (error: Exception) {
                lastError = error
                if (isProbeGone(error)) {
                    Timber.d("Blocklist mirror aborted (Tor SOCKS gone): %s", url)
                } else {
                    Timber.d("Blocklist mirror failed: %s (%s)", url, error.message)
                }
            }
        }
        throw lastError ?: IllegalStateException("No blocklist mirrors configured")
    }

    private fun fetchBodyToFile(client: OkHttpClient, url: String, dest: File) {
        val call = client.newCall(
            Request.Builder()
                .url(url)
                .header("User-Agent", "OnionVPN-DomainReputation/1.0")
                .header("Accept", "text/plain,*/*")
                .build(),
        )
        activeCall.set(call)
        val response = try {
            call.execute()
        } finally {
            activeCall.compareAndSet(call, null)
        }
        return response.use {
            if (!it.isSuccessful) {
                throw IllegalStateException("HTTP ${it.code} for $url")
            }
            val body = it.body ?: throw IllegalStateException("empty body for $url")
            body.byteStream().use { input ->
                dest.outputStream().use { output -> input.copyTo(output) }
            }
        }
    }

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
        val client = cachedHttpClient.get()?.takeIf { it.first == probePort }?.second
            ?: OkHttpClient.Builder()
                .proxy(proxy)
                .dns(TorSocksDns)
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(45, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .followRedirects(true)
                .followSslRedirects(true)
                .build()
                .also { cachedHttpClient.set(probePort to it) }
        Timber.i("Domain reputation download via Tor probe SOCKS :%d", probePort)
        return HttpTransport(client, viaTor = true)
    }

    /** Rename pre-unified HaGeZi cache files once. */
    private fun migrateLegacyFilenames() {
        val dir = listDir()
        val legacyMalware = File(dir, "hagezi-tif-mini.txt")
        val legacyTracking = File(dir, "hagezi-tracking.txt")
        val malware = File(dir, MALWARE_DB)
        val tracking = File(dir, TRACKING_DB)
        if (!malware.isFile && legacyMalware.isFile) {
            legacyMalware.copyTo(malware, overwrite = false)
            sourceCacheDir().mkdirs()
            legacyMalware.copyTo(sourceCacheFile("hagezi-tif-mini"), overwrite = false)
        }
        if (!tracking.isFile && legacyTracking.isFile) {
            legacyTracking.copyTo(tracking, overwrite = false)
        }
    }

    private fun listDir(): File =
        File(context.filesDir, "domain-reputation").also { it.mkdirs() }

    private fun sourceCacheDir(): File =
        File(listDir(), "sources").also { it.mkdirs() }

    private fun sourceCacheFile(id: String): File =
        File(sourceCacheDir(), "$id.txt")

    companion object {
        private const val MALWARE_DB = "malware.txt"
        private const val TRACKING_DB = "tracking.txt"
        private const val META_FILE = "last-success.txt"
        private const val VIA_TOR_FILE = "last-via-tor.txt"
        private const val REFRESH_INTERVAL_MS = 24L * 60L * 60L * 1000L
        private const val PROBE_WAIT_ATTEMPTS = 30
        private const val PROBE_WAIT_DELAY_MS = 500L
        private const val MERGE_DEDUPE_MAX = 400_000
    }
}

private data class HttpTransport(val client: OkHttpClient, val viaTor: Boolean)

data class DomainReputationStatus(
    val malwareEntries: Int = 0,
    val trackingEntries: Int = 0,
    /** Number of non-empty per-source cache files under `sources/`. */
    val sourceFilesCached: Int = 0,
    val lastSuccessEpochMs: Long = 0L,
    val lastError: String? = null,
    val updating: Boolean = false,
    val loadedFromCache: Boolean = false,
    /** True when the last successful download used Tor probe SOCKS. */
    val lastViaTor: Boolean = false,
)
