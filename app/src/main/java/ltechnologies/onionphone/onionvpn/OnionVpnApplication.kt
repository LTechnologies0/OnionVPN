package ltechnologies.onionphone.onionvpn

import android.app.Application
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import ltechnologies.onionphone.onionvpn.core.dnscrypt.DnsCryptProcessManager
import ltechnologies.onionphone.onionvpn.core.tor.control.TorControlEventFormatter
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlEvent
import ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.FirewallBridge
import ltechnologies.onionphone.onionvpn.firewall.InteractiveFirewallEngine
import ltechnologies.onionphone.onionvpn.logging.LogSource
import ltechnologies.onionphone.onionvpn.logging.ProcessLogSeverity
import ltechnologies.onionphone.onionvpn.logging.TunnelLogBuffer
import ltechnologies.onionphone.onionvpn.logging.TunnelLogTree
import timber.log.Timber

@HiltAndroidApp
class OnionVpnApplication : Application() {
    @Inject lateinit var tor: TorProcessManager
    @Inject lateinit var dnsCrypt: DnsCryptProcessManager
    @Inject lateinit var firewallEngine: InteractiveFirewallEngine

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()
        Timber.plant(TunnelLogTree())
        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
        }
        firewallEngine.start()
        FirewallBridge.engine = firewallEngine
        tor.onLogLine = { line ->
            val err = ProcessLogSeverity.isError(LogSource.TOR, line)
            if (err) Timber.tag("tor").e("%s", line)
            TunnelLogBuffer.append(LogSource.TOR, line, isError = err)
        }
        dnsCrypt.onLogLine = { line ->
            val err = ProcessLogSeverity.isError(LogSource.DNSCRYPT, line)
            if (err) Timber.tag("dnscrypt").e("%s", line)
            TunnelLogBuffer.append(LogSource.DNSCRYPT, line, isError = err)
        }
        appScope.launch {
            tor.controlEvents.collect { event ->
                // BW floods the log buffer — skip.
                if (event is TorControlEvent.Bandwidth) return@collect
                val line = TorControlEventFormatter.format(event)
                val err = event is TorControlEvent.Notice &&
                    (event.severity == "WARN" || event.severity == "ERR")
                TunnelLogBuffer.append(LogSource.TOR, line, isError = err)
            }
        }
    }
}
