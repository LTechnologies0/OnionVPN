package ltechnologies.onionphone.onionvpn.core.tor.kotlintor

import android.content.Context
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.suspendCancellableCoroutine
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.model.observability.OpTrace
import org.kotlintor.android.KotlinTorEngine
import org.kotlintor.android.VpnTunnel
import org.kotlintor.config.ListenSpec
import timber.log.Timber
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * In-process kotlin-tor engine for OnionVPN **HEV_SOCKS** (+ DNSCrypt).
 * Does **not** own TUN (hev remains the data plane; not onionmasq / not a new TunDataPlane).
 *
 * Start contract:
 * 1. [attachVpn] / [KotlinTorEngine.attachVpn] **before** listeners so
 *    `PlatformNatives.protectSocketFd` excludes OR dials from the VPN.
 * 2. [KotlinTorEngine.startWithPorts] binds allocated socks / DNSCrypt / probe / DNSPort.
 * 3. Ready only after SOCKS + DNSPort accept — DNSCrypt must wait for [TorProcessManager.start].
 * 4. NEWNYM via [KotlinTorEngine.newnym] (SocksPort stays up; soft debounce like little-t).
 */
internal class KotlinTorRuntime(
    private val context: Context,
) {
    @Volatile
    private var engine: KotlinTorEngine? = null
    private val running = AtomicBoolean(false)
    private val lastPorts = AtomicReference<TunnelRuntimePorts?>(null)
    private val protectRef = AtomicReference<((Int) -> Boolean)?>(null)

    val statusFile: File
        get() = File(context.filesDir, "kotlin-tor/status").also { it.parentFile?.mkdirs() }

    fun isRunning(): Boolean = running.get() && engine?.isRunning == true

    /** Call under VpnService **before** [start] so uplink OR sockets are protected. */
    fun attachVpn(protect: (Int) -> Boolean) {
        protectRef.set(protect)
        val eng = engine ?: KotlinTorEngine(context).also { engine = it }
        eng.attachVpn(object : VpnTunnel {
            override fun protect(fd: Int): Boolean = protect(fd)
        })
        Timber.i("kotlin-tor attachVpn protect wired")
    }

    suspend fun start(
        ports: TunnelRuntimePorts,
        @Suppress("UNUSED_PARAMETER") preferences: TunnelPreferences,
        protect: ((Int) -> Boolean)? = null,
    ) {
        stop()
        lastPorts.set(ports)
        if (protect != null) protectRef.set(protect)
        val eng = KotlinTorEngine(context)
        engine = eng
        protectRef.get()?.let { p ->
            eng.attachVpn(object : VpnTunnel {
                override fun protect(fd: Int): Boolean = p(fd)
            })
        }
        writeStatus(ports, ready = false)
        OpTrace.info(
            "kotlin-tor",
            "Starting socks=${ports.torSocksPort} dnsCrypt=${ports.torDnsCryptSocksPort} " +
                "probe=${ports.torProbeSocksPort} dns=${ports.torDnsPort} " +
                "protect=${protectRef.get() != null}",
        )
        suspendCancellableCoroutine { cont ->
            eng.startWithPorts(
                socks = ListenSpec("127.0.0.1", ports.torSocksPort),
                dnsCryptSocks = ListenSpec("127.0.0.1", ports.torDnsCryptSocksPort),
                probeSocks = ListenSpec("127.0.0.1", ports.torProbeSocksPort),
                dns = ListenSpec("127.0.0.1", ports.torDnsPort),
                onReady = {
                    running.set(true)
                    writeStatus(ports, ready = true)
                    if (cont.isActive) cont.resume(Unit)
                },
                onError = { t ->
                    running.set(false)
                    writeStatus(ports, ready = false, error = t.message)
                    if (cont.isActive) cont.resumeWithException(t)
                },
            )
        }
        Timber.i(
            "kotlin-tor ready socks=%d dnsCrypt=%d probe=%d dns=%d",
            eng.socksPort.takeIf { it > 0 } ?: ports.torSocksPort,
            eng.dnsCryptSocksPort.takeIf { it > 0 } ?: ports.torDnsCryptSocksPort,
            eng.probeSocksPort.takeIf { it > 0 } ?: ports.torProbeSocksPort,
            eng.dnsPortBound.takeIf { it > 0 } ?: ports.torDnsPort,
        )
    }

    /** Soft NEWNYM — SocksPort stays up. */
    fun newNym() {
        val eng = engine
        if (eng == null || !running.get()) {
            Timber.w("kotlin-tor newnym skipped — engine not running")
            return
        }
        eng.newnym()
        Timber.i("kotlin-tor newnym requested")
    }

    fun stop() {
        runCatching { engine?.stop() }
        engine = null
        running.set(false)
        lastPorts.get()?.let { writeStatus(it, ready = false) }
    }

    private fun writeStatus(ports: TunnelRuntimePorts, ready: Boolean, error: String? = null) {
        runCatching {
            statusFile.writeText(
                buildString {
                    appendLine("engine=KOTLIN_TOR")
                    appendLine("ready=$ready")
                    appendLine("socks=${ports.torSocksPort}")
                    appendLine("dnscrypt_socks=${ports.torDnsCryptSocksPort}")
                    appendLine("probe_socks=${ports.torProbeSocksPort}")
                    appendLine("dns=${ports.torDnsPort}")
                    appendLine("protect_attached=${protectRef.get() != null}")
                    if (error != null) appendLine("error=$error")
                    appendLine(
                        "note=attachVpn_protect_before_start;" +
                            "DNSCrypt_after_SOCKS+DNSPort_ready;" +
                            "NEWNYM_via_KotlinTorEngine",
                    )
                },
            )
        }
    }

    companion object {
        const val VERSION_LABEL = "kotlin-tor"
    }
}
