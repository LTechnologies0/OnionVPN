package ltechnologies.onionphone.onionvpn

import android.app.Application
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject
import ltechnologies.onionphone.onionvpn.core.dnscrypt.DnsCryptProcessManager
import ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager
import ltechnologies.onionphone.onionvpn.logging.LogSource
import ltechnologies.onionphone.onionvpn.logging.ProcessLogSeverity
import ltechnologies.onionphone.onionvpn.logging.TunnelLogBuffer
import ltechnologies.onionphone.onionvpn.logging.TunnelLogTree
import timber.log.Timber

@HiltAndroidApp
class OnionVpnApplication : Application() {
    @Inject lateinit var tor: TorProcessManager
    @Inject lateinit var dnsCrypt: DnsCryptProcessManager

    override fun onCreate() {
        super.onCreate()
        Timber.plant(TunnelLogTree())
        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
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
    }
}
