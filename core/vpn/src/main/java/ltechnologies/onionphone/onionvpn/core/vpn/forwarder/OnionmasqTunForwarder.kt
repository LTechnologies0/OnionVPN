package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import androidx.lifecycle.Observer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.launch
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelFailure
import ltechnologies.onionphone.onionvpn.core.model.observability.OpTrace
import ltechnologies.onionphone.onionvpn.core.model.stability.ProcessLogLevel
import ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService
import ltechnologies.onionphone.onionvpn.core.vpn.profile.TunForwarder
import ltechnologies.onionphone.onionvpn.core.vpn.onionmasq.TorNativeAppUids
import org.torproject.onionmasq.OnionMasq
import org.torproject.onionmasq.events.BootstrapEvent
import org.torproject.onionmasq.events.ClosedConnectionEvent
import org.torproject.onionmasq.events.FailedConnectionEvent
import org.torproject.onionmasq.events.NewConnectionEvent
import org.torproject.onionmasq.events.NewDirectoryEvent
import org.torproject.onionmasq.events.OnionmasqEvent
import timber.log.Timber

/**
 * Tor-VPN-style data plane: VpnService TUN → [TunDnsMux] → socketpair → onionmasq (smoltcp→Arti).
 *
 * DNSCrypt divert stays on [TunDnsMux]; DNSCrypt upstream still needs a Tor SOCKS sidecar
 * (arti-mobile interim or onionmasq SOCKS when patched) — not provided by this forwarder.
 */
class OnionmasqTunForwarder(
    private val context: Context,
    private val dnsMode: DnsResolverMode = DnsResolverMode.DNSCRYPT_MUX,
    private val bridgeLines: String? = null,
    private val exitCountryCode: String? = null,
    private val onFatal: ((Throwable) -> Unit)? = null,
    private val onBootstrap: ((BootstrapEvent) -> Unit)? = null,
    private val onOnionmasqEvent: ((OnionmasqEvent) -> Unit)? = null,
) : TunForwarder {
    private val supervisor = SupervisorJob()
    private val scope = CoroutineScope(supervisor + Dispatchers.IO)
    private val worker = AtomicReference<Job?>(null)
    private val running = AtomicBoolean(false)
    /**
     * True once we have handed a TUN fd to [OnionMasq.start] (or are about to).
     * Native [OnionMasq.stop]/[OnionMasqJni.closeProxy] **aborts** (Rust unwrap) if the
     * control channel was never opened — [runCatching] cannot catch SIGABRT.
     */
    private val proxyOwned = AtomicBoolean(false)
    private var dnsMux: TunDnsMux? = null
    private var omEnd: ParcelFileDescriptor? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private var eventObserver: Observer<OnionmasqEvent>? = null

    override fun start(
        tunFd: ParcelFileDescriptor,
        socksHost: String,
        socksPort: Int,
        dnsCryptPort: Int,
        torDnsPort: Int,
        synthesizeOnionAutomap: Boolean,
    ) {
        OpTrace.step("onionmasq", "start dnsCrypt=$dnsCryptPort", ProcessLogLevel.INFO) {
            // Tear down a prior start on *this* instance only. Never call closeProxy when
            // onionmasq was not started — that path SIGABRTs inside libonionmasq_mobile.so
            // (seen on 0.3.45: startForwarder → stop → closeProxy unwrap_failed).
            stop()
            if (dnsMode != DnsResolverMode.DNSCRYPT_MUX) {
                Timber.i("dnsMode=$dnsMode coerced to DNSCRYPT_MUX divert for onionmasq")
            }
            try {
                OnionMasq.init(context.applicationContext)
            } catch (error: Throwable) {
                throw TunnelFailure.ForwarderDead(
                    "OnionMasq.init failed (native lib?): ${error.message}",
                    error,
                )
            }
            // Bind protect() after init — Tor VPN order (init then bindVPNService).
            runCatching { OnionMasq.bindVPNService(OnionVpnService::class.java) }
                .onFailure { Timber.w(it, "OnionMasq.bindVPNService after init failed") }

            val pair = HevSocks5TunForwarder.createPacketSocketPair()
            val onionEnd = pair[0]
            val muxEnd = pair[1]
            omEnd = onionEnd

            val divertDns = true
            val mux = TunDnsMux(
                context = context,
                tunFd = tunFd.dup(),
                hevFd = muxEnd,
                dnsCryptHost = TunnelEndpoints.LOOPBACK,
                dnsCryptPort = dnsCryptPort,
                vpnDnsAddress = TunnelEndpoints.VPN_DNS_ADDRESS,
                divertDnsToDnsCrypt = divertDns,
                torDnsHost = TunnelEndpoints.LOOPBACK,
                torDnsPort = torDnsPort,
                synthesizeOnionAutomap = synthesizeOnionAutomap,
                onFatal = { error ->
                    Timber.e(error, "TunDnsMux died (onionmasq path)")
                    onFatal?.invoke(error)
                },
            )
            dnsMux = mux
            mux.start()

            // Must observe before OnionMasq.start — BootstrapEvent can fire immediately;
            // a post{} race would miss ready-for-traffic and fail-closed after ~20s.
            attachEventObserver()
            exitCountryCode?.takeIf { it.isNotBlank() }?.let { cc ->
                runCatching { OnionMasq.setCountryCode(cc) }
                    .onFailure { Timber.w(it, "setCountryCode($cc) failed") }
            }
            runCatching {
                val uids = TorNativeAppUids.resolve(context)
                if (uids.isNotEmpty()) {
                    OnionMasq.setExcludedUids(uids)
                    Timber.i("onionmasq setExcludedUids count=%d", uids.size)
                }
            }.onFailure { Timber.w(it, "setExcludedUids failed") }

            running.set(true)
            val bridges = bridgeLines?.takeIf { it.isNotBlank() }
            val job = scope.launch {
                try {
                    // Transfer ownership of the socketpair end to native — do not close after.
                    val fd = onionEnd.detachFd()
                    omEnd = null
                    proxyOwned.set(true)
                    Timber.i(
                        "Starting OnionMasq on mux fd=%d bridges=%s",
                        fd,
                        bridges != null,
                    )
                    // Blocking until closeProxy — Tor VPN pattern.
                    OnionMasq.start(fd, bridges)
                } catch (error: Exception) {
                    Timber.e(error, "OnionMasq exited")
                    onFatal?.invoke(
                        TunnelFailure.ForwarderDead(
                            "onionmasq exited: ${error.message}",
                            error,
                        ),
                    )
                } finally {
                    running.set(false)
                    proxyOwned.set(false)
                }
            }
            worker.set(job)
        }
    }

    override fun stop() {
        OpTrace.debug("onionmasq", "stop")
        running.set(false)
        proxyOwned.set(false)
        detachEventObserver()
        // closeProxy aborts (Rust unwrap → SIGABRT) when the control channel was never
        // opened. isRunning() is the only safe gate — runCatching cannot catch abort.
        val nativeUp = runCatching { OnionMasq.isRunning() }.getOrDefault(false)
        if (nativeUp) {
            runCatching { OnionMasq.stop() }
                .onFailure { Timber.w(it, "OnionMasq.stop failed") }
        } else {
            Timber.d("OnionMasq.stop skipped — proxy not running")
        }
        dnsMux?.stop()
        dnsMux = null
        worker.getAndSet(null)?.cancel()
        supervisor.cancelChildren()
        // Only if start() failed before detachFd(); after detach, native owns the fd.
        runCatching { omEnd?.close() }
        omEnd = null
    }

    fun isRunning(): Boolean = running.get() && OnionMasq.isRunning()

    private fun attachEventObserver() {
        val observer = Observer<OnionmasqEvent> { event ->
            when (event) {
                is BootstrapEvent -> onBootstrap?.invoke(event)
                is NewConnectionEvent,
                is FailedConnectionEvent,
                is ClosedConnectionEvent,
                is NewDirectoryEvent,
                -> Unit
            }
            onOnionmasqEvent?.invoke(event)
        }
        eventObserver = observer
        // Never latch-wait on Main — post+await would deadlock.
        if (Looper.myLooper() == Looper.getMainLooper()) {
            OnionMasq.getEventObservable().observeForever(observer)
            return
        }
        val attached = CountDownLatch(1)
        mainHandler.post {
            try {
                OnionMasq.getEventObservable().observeForever(observer)
            } finally {
                attached.countDown()
            }
        }
        if (!attached.await(2, TimeUnit.SECONDS)) {
            Timber.w("onionmasq event observer attach timed out — bootstrap may be missed")
        }
    }

    private fun detachEventObserver() {
        val observer = eventObserver ?: return
        eventObserver = null
        if (Looper.myLooper() == Looper.getMainLooper()) {
            runCatching { OnionMasq.getEventObservable().removeObserver(observer) }
            return
        }
        val detached = CountDownLatch(1)
        mainHandler.post {
            try {
                runCatching { OnionMasq.getEventObservable().removeObserver(observer) }
            } finally {
                detached.countDown()
            }
        }
        runCatching { detached.await(2, TimeUnit.SECONDS) }
    }
}
