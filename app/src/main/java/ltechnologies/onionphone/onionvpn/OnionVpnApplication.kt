package ltechnologies.onionphone.onionvpn

import android.app.Application
import android.os.StrictMode
import android.util.Log
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import ltechnologies.onionphone.onionvpn.core.dnscrypt.DnsCryptProcessManager
import ltechnologies.onionphone.onionvpn.core.model.observability.DiagnosticsGate
import ltechnologies.onionphone.onionvpn.core.model.observability.OpTrace
import ltechnologies.onionphone.onionvpn.core.model.stability.ProcessLogLevel
import ltechnologies.onionphone.onionvpn.core.model.stability.StabilitySeverity
import ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager
import ltechnologies.onionphone.onionvpn.core.tor.control.TorControlEventFormatter
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlEvent
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.FirewallBridge
import ltechnologies.onionphone.onionvpn.diagnostics.NativeResourceProfiler
import ltechnologies.onionphone.onionvpn.firewall.InteractiveFirewallEngine
import ltechnologies.onionphone.onionvpn.logging.LogSource
import ltechnologies.onionphone.onionvpn.logging.ProcessLogSeverity
import ltechnologies.onionphone.onionvpn.logging.TunnelLogBuffer
import ltechnologies.onionphone.onionvpn.logging.TunnelLogTree
import ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore
import ltechnologies.onionphone.onionvpn.threat.repo.DomainReputationRepository
import timber.log.Timber

@HiltAndroidApp
class OnionVpnApplication : Application() {
    @Inject lateinit var tor: TorProcessManager
    @Inject lateinit var dnsCrypt: DnsCryptProcessManager
    @Inject lateinit var firewallEngine: InteractiveFirewallEngine
    @Inject lateinit var domainReputation: DomainReputationRepository
    @Inject lateinit var preferencesStore: TunnelPreferencesStore

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    lateinit var resourceProfiler: NativeResourceProfiler
        private set

    override fun onCreate() {
        super.onCreate()
        resourceProfiler = NativeResourceProfiler(
            context = this,
            scope = appScope,
            torChildPidProvider = { tor.nativeProcessPid() },
        )
        installObservability()
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
        appScope.launch {
            preferencesStore.preferences
                .map { it.noLogsEnabled }
                .distinctUntilChanged()
                .collect { DiagnosticsGate.setNoLogsEnabled(it) }
        }
        tor.onLogLine = { line ->
            if (DiagnosticsGate.enabled()) {
                val signal = ProcessLogSeverity.classify(LogSource.TOR, line)
                if (signal.isError) Timber.tag("tor").e("%s", line)
                else if (signal.isWarnOrWorse) Timber.tag("tor").w("%s", line)
                TunnelLogBuffer.append(LogSource.TOR, line, severity = signal.severity)
            }
        }
        dnsCrypt.onLogLine = { line ->
            if (DiagnosticsGate.enabled()) {
                val signal = ProcessLogSeverity.classify(LogSource.DNSCRYPT, line)
                if (signal.isError) Timber.tag("dnscrypt").e("%s", line)
                else if (signal.isWarnOrWorse) Timber.tag("dnscrypt").w("%s", line)
                TunnelLogBuffer.append(LogSource.DNSCRYPT, line, severity = signal.severity)
            }
        }
        var controlEventCount = 0L
        appScope.launch {
            tor.controlEvents.collect { event ->
                if (!DiagnosticsGate.enabled()) return@collect
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
                val severity = when {
                    event is TorControlEvent.Notice && event.severity == "ERR" ->
                        StabilitySeverity.ERROR
                    event is TorControlEvent.Notice && event.severity == "WARN" ->
                        StabilitySeverity.WARN
                    event is TorControlEvent.Notice && event.severity == "NOTICE" ->
                        StabilitySeverity.INFO
                    event is TorControlEvent.Notice &&
                        (event.severity == "INFO" || event.severity == "DEBUG") ->
                        StabilitySeverity.DEBUG
                    else ->
                        ProcessLogSeverity.classify(LogSource.TOR, line).severity
                }
                TunnelLogBuffer.append(LogSource.TOR, line, severity = severity)
            }
        }
    }

    private fun installObservability() {
        OpTrace.sink = OpTrace.Sink { level, module, message, error ->
            val text = if (error != null) {
                "[$module] $message (${error.message})"
            } else {
                "[$module] $message"
            }
            val priority = when (level) {
                ProcessLogLevel.TRACE -> Log.VERBOSE
                ProcessLogLevel.DEBUG -> Log.DEBUG
                ProcessLogLevel.INFO -> Log.INFO
                ProcessLogLevel.WARN -> Log.WARN
                ProcessLogLevel.ERROR, ProcessLogLevel.CRITICAL -> Log.ERROR
            }
            Timber.tag("optrace").log(priority, text)
            TunnelLogBuffer.append(LogSource.APP, text, severity = level.severity)
        }
        DiagnosticsGate.onDisabled = {
            TunnelLogBuffer.clearAll()
            resourceProfiler.stop()
        }
        DiagnosticsGate.onEnabled = {
            OpTrace.info("diagnostics", "diagnostics enabled")
        }
    }

    companion object {
        fun profiler(app: Application): NativeResourceProfiler? =
            (app as? OnionVpnApplication)?.resourceProfiler
    }
}
