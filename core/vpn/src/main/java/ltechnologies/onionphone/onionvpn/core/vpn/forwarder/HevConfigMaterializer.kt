package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.Os
import java.io.File
import java.io.FileOutputStream
import timber.log.Timber

/**
 * Materialize hev-socks5-tunnel YAML for [hev.sockstun.TProxyService.TProxyStartService]
 * without leaving the session password on durable `filesDir` (W4-10 #2).
 *
 * Prefer `memfd` (API 30+) → `/proc/self/fd/N`. Fall back to a private cache file
 * deleted on [Handle.close]. Native JNI still needs a filesystem path; `main_from_str`
 * is exported by libhev but not registered as a Java native.
 */
internal object HevConfigMaterializer {
    class Handle(
        val path: String,
        private val onClose: () -> Unit,
    ) : AutoCloseable {
        @Volatile private var closed = false
        override fun close() {
            if (closed) return
            closed = true
            runCatching { onClose() }
                .onFailure { Timber.w(it, "hev config materializer close failed") }
        }
    }

    fun materialize(yaml: String, cacheDir: File, nameHint: String): Handle {
        val bytes = yaml.toByteArray(Charsets.UTF_8)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return runCatching {
                val fd = Os.memfd_create(nameHint, 0)
                var written = 0
                while (written < bytes.size) {
                    val n = Os.write(fd, bytes, written, bytes.size - written)
                    if (n <= 0) error("memfd write short ($n)")
                    written += n
                }
                val pfd = ParcelFileDescriptor.dup(fd)
                runCatching { Os.close(fd) }
                Handle(path = "/proc/self/fd/${pfd.fd}") {
                    runCatching { pfd.close() }
                }
            }.getOrElse { error ->
                Timber.w(error, "memfd hev yaml failed — falling back to cache file")
                materializeCacheFile(bytes, cacheDir, nameHint)
            }
        }
        return materializeCacheFile(bytes, cacheDir, nameHint)
    }

    private fun materializeCacheFile(bytes: ByteArray, cacheDir: File, nameHint: String): Handle {
        if (!cacheDir.isDirectory) {
            cacheDir.mkdirs()
        }
        val file = File(cacheDir, "$nameHint-${System.nanoTime()}.yaml")
        FileOutputStream(file).use { it.write(bytes) }
        runCatching {
            file.setReadable(false, false)
            file.setReadable(true, true)
            file.setWritable(false, false)
            file.setWritable(true, true)
        }
        return Handle(path = file.absolutePath) {
            runCatching { file.delete() }
        }
    }
}
