package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import android.content.Context
import ltechnologies.onionphone.onionvpn.core.model.TorEngine
import ltechnologies.onionphone.onionvpn.core.model.TunDataPlane
import timber.log.Timber
import java.io.File

/**
 * Selects TUN→Tor forwarder. onionmasq path is gated on native availability + Arti.
 *
 * **Arti policy:** when `libonionmasq_mobile.so` is present, Arti always uses
 * [TunDataPlane.ONIONMASQ] (single TorClient). HEV is only for C Tor or Arti
 * without the native library.
 */
object TunDataPlaneFactory {
    fun resolve(
        context: Context,
        requested: TunDataPlane,
        engine: TorEngine,
    ): TunDataPlane {
        if (engine == TorEngine.ARTI && isOnionmasqNativePresent(context)) {
            if (requested != TunDataPlane.ONIONMASQ) {
                Timber.i("Arti + onionmasq native — forcing ONIONMASQ (was %s)", requested)
            }
            return TunDataPlane.ONIONMASQ
        }
        if (requested == TunDataPlane.ONIONMASQ) {
            if (engine != TorEngine.ARTI) {
                Timber.w("onionmasq requires Arti — falling back to HEV_SOCKS")
                return TunDataPlane.HEV_SOCKS
            }
            Timber.w("libonionmasq_mobile.so missing — falling back to HEV_SOCKS")
            return TunDataPlane.HEV_SOCKS
        }
        return TunDataPlane.HEV_SOCKS
    }

    /** File presence only — never [System.loadLibrary] (would abort on missing). */
    fun isOnionmasqNativePresent(context: Context): Boolean {
        val dir = context.applicationInfo.nativeLibraryDir ?: return false
        return File(dir, "libonionmasq_mobile.so").isFile ||
            File(dir, "libonionmasq.so").isFile ||
            File(dir, "libonionmasq_jni.so").isFile
    }
}
