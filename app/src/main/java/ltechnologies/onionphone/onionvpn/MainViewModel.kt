package ltechnologies.onionphone.onionvpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import java.io.File
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import ltechnologies.onionphone.onionvpn.core.dnscrypt.DnsCryptProcessManager
import ltechnologies.onionphone.onionvpn.core.model.TunnelPhase
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelSnapshot
import ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager
import ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore
import ltechnologies.onionphone.onionvpn.tunnel.TunnelOrchestrator
import timber.log.Timber

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

    /** Serializes start/stop/restart/nym so toddler button-mashing cannot interleave. */
    private val actionMutex = Mutex()
    private var restartJob: Job? = null

    /** First DataStore emission (not the Compose initialValue). */
    suspend fun awaitStoredPreferences(): TunnelPreferences = preferencesStore.preferences.first()

    fun currentTorSocksPort(): Int? = tor.currentProbeSocksPort()

    fun prepareVpnPermission(activity: Activity): Intent? = VpnService.prepare(activity)

    fun startTunnel() {
        viewModelScope.launch {
            actionMutex.withLock {
                val snap = snapshot.value
                if (!snap.canStart) {
                    Timber.w("startTunnel ignored — phase=%s", snap.phase)
                    return@withLock
                }
                orchestrator.start(preferences.value)
            }
        }
    }

    /** Idle / Error only — do not interrupt Connected, Blocking, or in-flight start. */
    fun shouldAutoStartTunnel(prefs: TunnelPreferences, snap: TunnelSnapshot = snapshot.value): Boolean {
        if (!prefs.autoStartOnAppLaunch) return false
        return when (snap.phase) {
            TunnelPhase.Idle, TunnelPhase.Error -> true
            else -> false
        }
    }

    fun stopTunnel() {
        viewModelScope.launch {
            actionMutex.withLock {
                val snap = snapshot.value
                if (!snap.canStop) {
                    Timber.w("stopTunnel ignored — phase=%s", snap.phase)
                    return@withLock
                }
                restartJob?.cancel()
                restartJob = null
                orchestrator.stop()
            }
        }
    }

    fun newNym() {
        viewModelScope.launch {
            actionMutex.withLock {
                val snap = snapshot.value
                if (!snap.canNewNym) {
                    Timber.w(
                        "newNym ignored — phase=%s refreshing=%s",
                        snap.phase,
                        snap.identityRefreshing,
                    )
                    return@withLock
                }
                orchestrator.newNym()
            }
        }
    }

    fun savePreferences(prefs: TunnelPreferences, restartIfConnected: Boolean = true) {
        viewModelScope.launch {
            actionMutex.withLock {
                preferencesStore.update { prefs }
                val phase = snapshot.value.phase
                when {
                    restartIfConnected &&
                        (phase == TunnelPhase.Connected || phase == TunnelPhase.Blocking) -> {
                        enqueueRestartLocked(prefs)
                    }
                    phase == TunnelPhase.Connected -> {
                        // Live apply without full tunnel restart (Orbot-style SETCONF where possible).
                        orchestrator.applyCircuitTiming(prefs)
                        withContext(Dispatchers.IO) {
                            tor.setBridgesLive(prefs.torBridges)
                            tor.setNodePrefsLive(
                                prefs.torEntryNodes,
                                prefs.torExitNodes,
                                prefs.torExcludeNodes,
                            )
                            if (dnsCrypt.isRunning()) {
                                dnsCrypt.applyPreferences(prefs.dnsCryptServerName, prefs)
                                    .onFailure { Timber.w(it, "Live DNSCrypt prefs apply failed") }
                            }
                        }
                    }
                }
            }
        }
    }

    suspend fun readTorrc(): String = withContext(Dispatchers.IO) {
        tor.torrcFile.takeIf { it.exists() }?.readText().orEmpty()
    }

    suspend fun readDnsCryptToml(): String = withContext(Dispatchers.IO) {
        dnsCrypt.configFile.takeIf { it.exists() }?.readText().orEmpty()
    }

    fun saveTorrc(content: String) {
        viewModelScope.launch {
            actionMutex.withLock {
                withContext(Dispatchers.IO) { writeConfigFile(tor.torrcFile, content) }
                if (snapshot.value.phase == TunnelPhase.Connected ||
                    snapshot.value.phase == TunnelPhase.Blocking
                ) {
                    enqueueRestartLocked(preferences.value)
                }
            }
        }
    }

    fun saveDnsCryptToml(content: String) {
        viewModelScope.launch {
            actionMutex.withLock {
                withContext(Dispatchers.IO) { writeConfigFile(dnsCrypt.configFile, content) }
                if (snapshot.value.phase == TunnelPhase.Connected ||
                    snapshot.value.phase == TunnelPhase.Blocking
                ) {
                    enqueueRestartLocked(preferences.value)
                }
            }
        }
    }

    /**
     * Coalesce stop→start: cancel any pending restart wait, stop once, wait for Idle, then start.
     * Must be called under [actionMutex].
     */
    private fun enqueueRestartLocked(prefs: TunnelPreferences) {
        restartJob?.cancel()
        restartJob = viewModelScope.launch {
            try {
                Timber.i("Coalesced tunnel restart begin")
                orchestrator.stop()
                val idle = withTimeoutOrNull(20_000L) {
                    snapshot.first {
                        it.phase == TunnelPhase.Idle || it.phase == TunnelPhase.Error
                    }
                }
                if (idle == null) {
                    Timber.w("Restart wait timed out — starting anyway")
                }
                kotlinx.coroutines.delay(400)
                actionMutex.withLock {
                    if (snapshot.value.canStart) {
                        orchestrator.start(prefs)
                    } else {
                        Timber.w("Restart aborted — phase=%s", snapshot.value.phase)
                    }
                }
            } catch (e: Exception) {
                Timber.w(e, "Coalesced restart cancelled or failed")
            }
        }
    }

    private fun writeConfigFile(file: File, content: String) {
        file.parentFile?.mkdirs()
        file.writeText(content)
    }
}
