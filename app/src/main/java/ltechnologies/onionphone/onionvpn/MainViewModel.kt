package ltechnologies.onionphone.onionvpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import java.io.File
import javax.inject.Inject
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import ltechnologies.onionphone.onionvpn.core.dnscrypt.DnsCryptProcessManager
import ltechnologies.onionphone.onionvpn.core.model.TunnelPhase
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelSnapshot
import ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager
import ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore
import ltechnologies.onionphone.onionvpn.tunnel.TunnelOrchestrator

@HiltViewModel
class MainViewModel @Inject constructor(
    private val orchestrator: TunnelOrchestrator,
    private val preferencesStore: TunnelPreferencesStore,
    private val tor: TorProcessManager,
    private val dnsCrypt: DnsCryptProcessManager,
) : ViewModel() {
    val snapshot: StateFlow<TunnelSnapshot> = orchestrator.snapshot.stateIn(
        scope = viewModelScope,
        started = SharingStarted.Eagerly,
        initialValue = TunnelSnapshot(),
    )

    val preferences: StateFlow<TunnelPreferences> = preferencesStore.preferences.stateIn(
        scope = viewModelScope,
        started = SharingStarted.Eagerly,
        initialValue = TunnelPreferences(),
    )

    fun prepareVpnPermission(activity: Activity): Intent? = VpnService.prepare(activity)

    fun startTunnel() {
        orchestrator.start(preferences.value)
    }

    fun stopTunnel() {
        orchestrator.stop()
    }

    fun newNym() {
        orchestrator.newNym()
    }

    fun savePreferences(prefs: TunnelPreferences, restartIfConnected: Boolean = true) {
        viewModelScope.launch {
            preferencesStore.update { prefs }
            if (restartIfConnected && snapshot.value.phase == TunnelPhase.Connected) {
                orchestrator.stop()
                // Brief delay so stop settles before restart.
                kotlinx.coroutines.delay(750)
                orchestrator.start(prefs)
            }
        }
    }

    fun readTorrc(): String = tor.torrcFile.takeIf { it.exists() }?.readText().orEmpty()

    fun readDnsCryptToml(): String = dnsCrypt.configFile.takeIf { it.exists() }?.readText().orEmpty()

    fun saveTorrc(content: String) {
        viewModelScope.launch {
            writeConfigFile(tor.torrcFile, content)
            if (snapshot.value.phase == TunnelPhase.Connected) {
                orchestrator.stop()
                kotlinx.coroutines.delay(750)
                orchestrator.start(preferences.value)
            }
        }
    }

    fun saveDnsCryptToml(content: String) {
        viewModelScope.launch {
            writeConfigFile(dnsCrypt.configFile, content)
            if (snapshot.value.phase == TunnelPhase.Connected) {
                orchestrator.stop()
                kotlinx.coroutines.delay(750)
                orchestrator.start(preferences.value)
            }
        }
    }

    private fun writeConfigFile(file: File, content: String) {
        file.parentFile?.mkdirs()
        file.writeText(content)
    }
}
