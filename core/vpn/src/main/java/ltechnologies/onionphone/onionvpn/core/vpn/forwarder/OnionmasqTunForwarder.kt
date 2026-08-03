package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
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
import ltechnologies.onionphone.onionvpn.core.vpn.onionmasq.OnionmasqNativeGate
import ltechnologies.onionphone.onionvpn.core.vpn.onionmasq.TorNativeAppUids
import org.torproject.onionmasq.ConnectivityHandler
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
     *
     * Native [OnionMasq.stop] / [OnionMasq.isRunning] call `OnionmasqMobile::get()`, which
     * **expect()-aborts** (SIGABRT; panic=abort) when `init()` has not run. [runCatching]
     * cannot catch that. Gate every native stop/probe on this flag — never on JNI isRunning.
     *
     * Regression: 0.3.46 stop() probed [OnionMasq.isRunning] before init → tombstone
     * `Java_org_torproject_onionmasq_OnionMasqJni_isRunning` → `unwrap_failed`.
     */
    private val proxyOwned = AtomicBoolean(false)
    private var dnsMux: TunDnsMux? = null
    private var omEnd: ParcelFileDescriptor? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private var eventObserver: Observer<OnionmasqEvent>? = null
    /** Tor VPN parity: drives OnionMasqJni.setInternetConnectivity on uplink changes. */
    private var connectivityHandler: ConnectivityHandler? = null
    /**
     * Tor VPN [AppQueryReceiver] parity: refresh Tor-over-Tor UID excludes when packages
     * are installed/removed (setExcludedUids was previously one-shot at start).
     */
    private var packageReceiver: BroadcastReceiver? = null

    override fun start(
        tunFd: ParcelFileDescriptor,
        socksHost: String,
        socksPort: Int,
        dnsCryptPort: Int,
        torDnsPort: Int,
        synthesizeOnionAutomap: Boolean,
    ) {
        OpTrace.step("onionmasq", "start dnsCrypt=$dnsCryptPort", ProcessLogLevel.INFO) {
            // Tear down a prior start on *this* instance only. stop() must not touch JNI
            // unless proxyOwned — start() runs before init on a fresh instance.
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
            // Wait for binder: early protect() with null binder returns false → Arti uplink fail.
            runCatching { OnionMasq.bindVPNService(OnionVpnService::class.java) }
                .onFailure { Timber.w(it, "OnionMasq.bindVPNService after init failed") }
            if (!OnionMasq.awaitProtectBinder(5_000L)) {
                Timber.e("OnionMasq protect binder not ready after 5s — aborting start")
                throw TunnelFailure.ForwarderDead(
                    "OnionMasq protect() binder not connected (VpnService bind timeout)",
                )
            }
            // Tor VPN: ConnectivityHandler.register() while proxy lifetime is active.
            runCatching {
                connectivityHandler?.unregister()
                val handler = ConnectivityHandler(context.applicationContext)
                handler.register()
                connectivityHandler = handler
                // Handler.register() seeds INTERNET-only; reseed VALIDATED (Tor sample parity).
                if (OnionMasq.isInitialized()) {
                    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE)
                        as? android.net.ConnectivityManager
                    val caps = cm?.activeNetwork?.let { cm.getNetworkCapabilities(it) }
                    val validated = caps?.hasCapability(
                        android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED,
                    ) == true
                    runCatching {
                        org.torproject.onionmasq.OnionMasqJni.setInternetConnectivity(validated)
                    }.onFailure { Timber.d(it, "reseed VALIDATED connectivity after register") }
                }
                Timber.i("onionmasq ConnectivityHandler registered")
            }.onFailure { Timber.w(it, "ConnectivityHandler.register failed") }

            try {
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
                // Sample ArtiVpnService: setExcludedUids immediately before start while
                // isRunning() is still false — do not gate on isRunning() here.
                applyExcludedUidsPreStart()
                registerPackageReceiver()

                running.set(true)
                val bridges = bridgeLines?.takeIf { it.isNotBlank() }
                val job = scope.launch {
                    var detachedFd = -1
                    try {
                        // Transfer ownership of the socketpair end to native — do not close after
                        // a successful handoff. If start() throws before runProxy, reclaim the fd.
                        val fd = onionEnd.detachFd()
                        detachedFd = fd
                        omEnd = null
                        proxyOwned.set(true)
                        Timber.i(
                            "Starting OnionMasq on mux fd=%d bridges=%s",
                            fd,
                            bridges != null,
                        )
                        // Blocking until closeProxy — Tor VPN pattern.
                        OnionMasq.start(fd, bridges)
                        detachedFd = -1 // native owns fd for the lifetime of runProxy
                    } catch (error: Exception) {
                        if (detachedFd >= 0) {
                            runCatching {
                                ParcelFileDescriptor.adoptFd(detachedFd).close()
                            }.onFailure { Timber.w(it, "close orphaned onionmasq fd") }
                            detachedFd = -1
                            proxyOwned.set(false)
                        }
                        Timber.e(error, "OnionMasq exited")
                        onFatal?.invoke(
                            TunnelFailure.ForwarderDead(
                                "onionmasq exited: ${error.message}",
                                error,
                            ),
                        )
                    } finally {
                        running.set(false)
                        // start() has returned (drop_command_sender already ran). Clear ownership
                        // so a later stop() on this instance does not re-enter closeProxy needlessly.
                        proxyOwned.set(false)
                    }
                }
                worker.set(job)
            } catch (error: Throwable) {
                Timber.e(error, "onionmasq start failed — rolling back")
                runCatching { stop() }
                throw error
            }
        }
    }

    override fun stop() {
        OpTrace.debug("onionmasq", "stop")
        running.set(false)
        detachEventObserver()
        unregisterPackageReceiver()
        runCatching { connectivityHandler?.unregister() }
            .onFailure { Timber.w(it, "ConnectivityHandler.unregister failed") }
        connectivityHandler = null
        // Ownership gate only — do NOT call OnionMasq.isRunning() here.
        // Pre-init isRunning/closeProxy → OnionmasqMobile::get expect → SIGABRT.
        val owned = proxyOwned.getAndSet(false)
        if (OnionmasqNativeGate.mayStopNativeProxy(owned)) {
            runCatching { OnionMasq.stop() }
                .onFailure { Timber.w(it, "OnionMasq.stop failed") }
        } else {
            Timber.d("OnionMasq.stop skipped — proxy not owned (pre-init or never started)")
        }
        runCatching { OnionMasq.unbindVPNService() }
            .onFailure { Timber.w(it, "OnionMasq.unbindVPNService failed") }
        dnsMux?.stop()
        dnsMux = null
        worker.getAndSet(null)?.cancel()
        supervisor.cancelChildren()
        // Only if start() failed before detachFd(); after detach, native owns the fd.
        runCatching { omEnd?.close() }
        omEnd = null
    }

    fun isRunning(): Boolean = running.get() && proxyOwned.get()

    /** Pre-start: init required, running not required (sample Tor VPN pattern). */
    private fun applyExcludedUidsPreStart() {
        runCatching {
            if (!OnionMasq.isInitialized()) return
            val uids = TorNativeAppUids.resolve(context)
            OnionMasq.setExcludedUids(uids)
            Timber.i("onionmasq setExcludedUids (pre-start) count=%d", uids.size)
        }.onFailure { Timber.w(it, "setExcludedUids pre-start failed") }
    }

    /** Post-start refresh when packages are installed/updated/removed. */
    private fun refreshExcludedUids() {
        runCatching {
            if (!OnionMasq.isInitialized()) return
            if (!OnionMasq.isRunning() && !proxyOwned.get()) return
            val uids = TorNativeAppUids.resolve(context)
            OnionMasq.setExcludedUids(uids)
            Timber.i("onionmasq setExcludedUids (refresh) count=%d", uids.size)
        }.onFailure { Timber.w(it, "setExcludedUids refresh failed") }
    }

    private fun registerPackageReceiver() {
        unregisterPackageReceiver()
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_PACKAGE_ADDED,
                    Intent.ACTION_PACKAGE_REMOVED,
                    Intent.ACTION_PACKAGE_REPLACED,
                    -> {
                        refreshExcludedUids()
                        if (intent.action == Intent.ACTION_PACKAGE_REMOVED ||
                            intent.action == Intent.ACTION_PACKAGE_REPLACED
                        ) {
                            val uid = intent.getIntExtra(Intent.EXTRA_UID, -1)
                            if (uid >= 0) {
                                OnionVpnService.circuitRepository.dropApp(uid)
                                runCatching {
                                    if (OnionMasq.isInitialized() && OnionMasq.isRunning()) {
                                        OnionMasq.refreshCircuitsForApp(uid.toLong())
                                    }
                                }.onFailure {
                                    Timber.w(it, "onionmasq refreshCircuitsForApp on package remove")
                                }
                            }
                        }
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                @Suppress("UnspecifiedRegisterReceiverFlag")
                context.registerReceiver(receiver, filter)
            }
            packageReceiver = receiver
            Timber.i("onionmasq package exclude receiver registered")
        }.onFailure { Timber.w(it, "package exclude receiver register failed") }
    }

    private fun unregisterPackageReceiver() {
        val receiver = packageReceiver ?: return
        packageReceiver = null
        runCatching { context.unregisterReceiver(receiver) }
            .onFailure { Timber.w(it, "package exclude receiver unregister failed") }
    }

    private fun attachEventObserver() {
        val observer = Observer<OnionmasqEvent> { event ->
            when (event) {
                is BootstrapEvent -> onBootstrap?.invoke(event)
                is NewConnectionEvent,
                is FailedConnectionEvent,
                is ClosedConnectionEvent,
                is NewDirectoryEvent,
                -> Unit
                else -> Unit // DNSConnectivityEvent / ConnectivityEvent → app observer
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
            throw TunnelFailure.ForwarderDead(
                "onionmasq event observer attach timed out — BootstrapEvent would be missed",
            )
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
