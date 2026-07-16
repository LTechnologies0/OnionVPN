package ltechnologies.onionphone.onionvpn

import android.app.Application
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject
import ltechnologies.onionphone.onionvpn.core.dnscrypt.DnsCryptProcessManager
import ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager
import ltechnologies.onionphone.onionvpn.logging.LogSource
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
        tor.onLogLine = { TunnelLogBuffer.append(LogSource.TOR, it) }
        dnsCrypt.onLogLine = { TunnelLogBuffer.append(LogSource.DNSCRYPT, it) }
    }
}
