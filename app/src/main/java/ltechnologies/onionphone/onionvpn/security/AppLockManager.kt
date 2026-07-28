package ltechnologies.onionphone.onionvpn.security

import android.app.KeyguardManager
import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class AppLockState {
    /** No device PIN/pattern — lock unavailable; UI allowed with warning. */
    DEVICE_INSECURE,
    /** Waiting for system credential / biometric. */
    LOCKED,
    /** Authenticated for this foreground session. */
    UNLOCKED,
}

/**
 * Optional UI gate tied to the Android device lock (GrapheneOS / AOSP Keyguard).
 *
 * Does **not** stop [ltechnologies.onionphone.onionvpn.service.TunnelForegroundService] —
 * the tunnel stays up while the settings UI is locked (unlike messaging apps that pause
 * network until unlock).
 */
@Singleton
class AppLockManager @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val keyguard = context.getSystemService(KeyguardManager::class.java)

    @Volatile
    var enabled: Boolean = true
        set(value) {
            field = value
            refresh()
        }

    private val _state = MutableStateFlow(computeState())
    val state: StateFlow<AppLockState> = _state.asStateFlow()

    val isDeviceSecure: Boolean
        get() = keyguard?.isDeviceSecure == true

    val isUnlocked: Boolean
        get() = _state.value == AppLockState.UNLOCKED

    fun markUnlocked() {
        if (!enabled) {
            _state.value = AppLockState.UNLOCKED
            return
        }
        if (!isDeviceSecure) {
            _state.value = AppLockState.DEVICE_INSECURE
            return
        }
        _state.value = AppLockState.UNLOCKED
    }

    /** Re-lock when leaving the foreground (if lock is enabled). */
    fun lock() {
        if (!enabled) {
            _state.value = AppLockState.UNLOCKED
            return
        }
        if (!isDeviceSecure) {
            _state.value = AppLockState.DEVICE_INSECURE
            return
        }
        _state.value = AppLockState.LOCKED
    }

    fun refresh() {
        when {
            !enabled -> _state.value = AppLockState.UNLOCKED
            !isDeviceSecure -> _state.value = AppLockState.DEVICE_INSECURE
            _state.value == AppLockState.UNLOCKED -> Unit
            else -> _state.value = AppLockState.LOCKED
        }
    }

    private fun computeState(): AppLockState {
        if (!enabled) return AppLockState.UNLOCKED
        if (!isDeviceSecure) return AppLockState.DEVICE_INSECURE
        return AppLockState.LOCKED
    }
}
