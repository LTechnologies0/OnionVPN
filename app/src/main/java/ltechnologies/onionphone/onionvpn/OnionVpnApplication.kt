package ltechnologies.onionphone.onionvpn

import android.app.Application
import android.os.StrictMode
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
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
import ltechnologies.onionphone.onionvpn.threat.repo.DomainReputationRepository
import timber.log.Timber

@HiltAndroidApp
class OnionVpnApplication : Application() {
    @Inject lateinit var tor: TorProcessManager
    @Inject lateinit var dnsCrypt: DnsCryptProcessManager
    @Inject lateinit var firewallEngine: InteractiveFirewallEngine
    @Inject lateinit var domainReputation: DomainReputationRepository

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            StrictMode.setThreadPolicy(
                StrictMode.ThreadPolicy.Builder()
                    .detectAll()
                    .penaltyLog()
                    .build(),
            )
            StrictMode.setVmPolicy(
                StrictMode.VmPolicy.Builder()
                    .detectLeakedSqlLiteObjects()
                    .detectLeakedClosableObjects()
                    .penaltyLog()
                    .build(),
            )
        }
        Timber.plant(TunnelLogTree())
        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
        }
        FirewallBridge.engine = firewallEngine
        appScope.launch {
            delay(3_000)
            domainReputation.start()
        }
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
        var controlEventCount = 0L
        appScope.launch {
            tor.controlEvents.collect { event ->
                if (event is TorControlEvent.Bandwidth) return@collect
                if (event is TorControlEvent.Stream) return@collect
                controlEventCount++
                if ((controlEventCount and 0x1F) != 0L &&
                    event !is TorControlEvent.Notice &&
                    event !is TorControlEvent.Circuit
                ) {
                    return@collect
                }
                val line = TorControlEventFormatter.format(event)
                val err = event is TorControlEvent.Notice &&
                    (event.severity == "WARN" || event.severity == "ERR")
                TunnelLogBuffer.append(LogSource.TOR, line, isError = err)
            }
        }
    }
}
