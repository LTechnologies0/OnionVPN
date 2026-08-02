package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import androidx.lifecycle.Observer
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
                    Timber.i(
                        "Starting OnionMasq on mux fd=${onionEnd.fd} bridges=${bridges != null}",
                    )
                    // Blocking until closeProxy — Tor VPN pattern.
                    OnionMasq.start(onionEnd.detachFd(), bridges)
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
                }
            }
            worker.set(job)
        }
    }

    override fun stop() {
        OpTrace.debug("onionmasq", "stop")
        running.set(false)
        detachEventObserver()
        runCatching { OnionMasq.stop() }
        dnsMux?.stop()
        dnsMux = null
        worker.getAndSet(null)?.cancel()
        supervisor.cancelChildren()
        omEnd?.close()
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
        mainHandler.post {
            OnionMasq.getEventObservable().observeForever(observer)
        }
    }

    private fun detachEventObserver() {
        val observer = eventObserver ?: return
        eventObserver = null
        mainHandler.post {
            runCatching { OnionMasq.getEventObservable().removeObserver(observer) }
        }
    }
}
