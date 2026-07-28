package ltechnologies.onionphone.onionvpn.core.tor

import android.content.Context
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import timber.log.Timber

class TorProcessManager(
    private val context: Context,
) {
    private var process: Process? = null
    private var logThread: Thread? = null
    private var runtimePorts: TunnelRuntimePorts? = null
    private var preferences: TunnelPreferences = TunnelPreferences()

    val configDirectory: File
        get() = File(context.filesDir, "tor").also { it.mkdirs() }

    val torrcFile: File
        get() = File(configDirectory, "torrc")

    val binaryFile: File
        get() = File(context.applicationInfo.nativeLibraryDir, "libtor.so")

    suspend fun start(
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences = TunnelPreferences(),
    ): Result<Unit> = withContext(Dispatchers.IO) {
        this@TorProcessManager.preferences = preferences
        runtimePorts = ports
        stopInternal()
        killOrphanedProcesses()
        try {
            ensureExecutable(binaryFile)
            writeTorrc(ports)
            val command = listOf(binaryFile.absolutePath, "-f", torrcFile.absolutePath)
            process = ProcessBuilder(command)
                .directory(configDirectory)
                .redirectErrorStream(true)
                .start()
            startLogPump(process!!)
            waitForBootstrap(ports)
            Timber.i(
                "Tor listening socks=${ports.torSocksPort} " +
                    "dnscryptSocks=${ports.torDnsCryptSocksPort} " +
                    "probeSocks=${ports.torProbeSocksPort} dns=${ports.torDnsPort}",
            )
            Result.success(Unit)
        } catch (error: Exception) {
            Timber.e(error, "Tor failed to start")
            stopInternal()
            runtimePorts = null
            Result.failure(error)
        }
    }

    suspend fun stop() = withContext(Dispatchers.IO) {
        stopInternal()
    }

    fun isRunning(): Boolean = process?.isAlive == true

    private fun startLogPump(proc: Process) {
        logThread = Thread {
            try {
                proc.inputStream.bufferedReader().useLines { lines ->
                    lines.forEach { line ->
                        Timber.tag(LOG_TAG).d(line)
                        onLogLine?.invoke(line)
                    }
                }
            } catch (_: Exception) {
                // Process stopped — ignore read interruption.
            }
        }.apply {
            name = "tor-log"
            isDaemon = true
            start()
        }
    }

    /** Optional sink for UI log buffers (set by app layer). */
    var onLogLine: ((String) -> Unit)? = null

    private suspend fun waitForBootstrap(
        ports: TunnelRuntimePorts,
        timeoutMs: Long = 120_000,
        pollMs: Long = 500,
    ) {
        val deadline = System.currentTimeMillis() + timeoutMs
        var lastError: Exception? = null
        while (System.currentTimeMillis() < deadline) {
            if (process?.isAlive != true) {
                throw IOException("Tor process exited before bootstrap")
            }
            try {
                if (
                    isSocksReady(ports.torSocksPort) &&
                    isSocksReady(ports.torDnsCryptSocksPort) &&
                    isSocksReady(ports.torProbeSocksPort) &&
                    isDnsPortReady(ports.torDnsPort)
                ) {
                    Timber.i("Tor bootstrap complete")
                    return
                }
            } catch (error: Exception) {
                lastError = error
            }
            delay(pollMs)
        }
        throw IOException("Tor bootstrap timed out", lastError)
    }

    private fun isSocksReady(port: Int): Boolean {
        Socket().use { socket ->
            socket.connect(
                InetSocketAddress(TunnelEndpoints.LOOPBACK, port),
                1_000,
            )
        }
        return true
    }

    private fun isDnsPortReady(port: Int): Boolean {
        val query = byteArrayOf(
            0x00, 0x01,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
            'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x00,
            0x00, 0x01,
            0x00, 0x01,
        )
        java.net.DatagramSocket().use { socket ->
            socket.soTimeout = 2_000
            socket.send(
                java.net.DatagramPacket(
                    query,
                    query.size,
                    java.net.InetAddress.getByName(TunnelEndpoints.LOOPBACK),
                    port,
                ),
            )
            val response = java.net.DatagramPacket(ByteArray(512), 512)
            socket.receive(response)
        }
        return true
    }

    private fun ensureExecutable(file: File) {
        if (!file.exists()) {
            throw IOException("Binary missing at ${file.absolutePath}")
        }
        if (!file.canExecute()) {
            file.setExecutable(true, false)
        }
    }

    private fun writeTorrc(ports: TunnelRuntimePorts) {
        torrcFile.writeText(
            TorConfigWriter.write(
                dataDirectory = configDirectory.absolutePath,
                socksPort = ports.torSocksPort,
                dnsCryptSocksPort = ports.torDnsCryptSocksPort,
                probeSocksPort = ports.torProbeSocksPort,
                dnsPort = ports.torDnsPort,
                preferences = preferences,
            ),
        )
    }

    companion object {
        const val LOG_TAG = "tor"
    }

    private fun stopInternal() {
        process?.destroyForcibly()
        runCatching { process?.waitFor() }
        process = null
        logThread?.interrupt()
        logThread = null
        runtimePorts = null
    }

    private fun killOrphanedProcesses() {
        runCatching {
            Runtime.getRuntime()
                .exec(arrayOf("sh", "-c", "pkill -f ${binaryFile.name} 2>/dev/null || true"))
                .waitFor()
        }
    }
}
