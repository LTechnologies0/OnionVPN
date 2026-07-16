package ltechnologies.onionphone.onionvpn.core.dnscrypt

import android.content.Context
import java.io.File
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import timber.log.Timber

class DnsCryptProcessManager(
    private val context: Context,
) {
    private var process: Process? = null
    private var logThread: Thread? = null
    private val listenerReady = AtomicBoolean(false)
    private val serverReady = AtomicBoolean(false)
    private var listenPort: Int? = null
    private var preferences: TunnelPreferences = TunnelPreferences()

    val configDirectory: File
        get() = File(context.filesDir, "dnscrypt").also { it.mkdirs() }

    val configFile: File
        get() = File(configDirectory, "dnscrypt-proxy.toml")

    val binaryFile: File
        get() = File(context.applicationInfo.nativeLibraryDir, "libdnscrypt-proxy.so")

    /** Optional sink for UI log buffers (set by app layer). */
    var onLogLine: ((String) -> Unit)? = null

    suspend fun start(
        serverName: String = "cloudflare",
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences = TunnelPreferences(),
    ): Result<Unit> = withContext(Dispatchers.IO) {
        this@DnsCryptProcessManager.preferences = preferences
        listenPort = ports.dnsCryptListenPort
        stopInternal()
        killOrphanedProcesses()
        listenerReady.set(false)
        serverReady.set(false)
        try {
            ensureExecutable(binaryFile)
            writeConfig(serverName.ifBlank { preferences.dnsCryptServerName }, ports)
            val command = listOf(
                binaryFile.absolutePath,
                "-config",
                configFile.absolutePath,
            )
            process = ProcessBuilder(command)
                .directory(configDirectory)
                .redirectErrorStream(true)
                .start()
            startLogPump(process!!)
            waitForListener(ports.dnsCryptListenPort)
            waitForLiveServer()
            Timber.i("DNSCrypt listening on ${ports.dnsCryptListenPort}")
            Result.success(Unit)
        } catch (error: Exception) {
            Timber.e(error, "DNSCrypt failed to start")
            stopInternal()
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
                        if (line.contains("Now listening to") || line.contains("live servers:")) {
                            listenerReady.set(true)
                        }
                        if (line.contains("live servers:") ||
                            (line.contains("[NOTICE]") && line.contains("OK") && line.contains("ms"))
                        ) {
                            serverReady.set(true)
                        }
                    }
                }
            } catch (_: Exception) {
                // Process stopped — ignore read interruption.
            }
        }.apply {
            name = "dnscrypt-log"
            isDaemon = true
            start()
        }
    }

    private suspend fun waitForLiveServer(
        timeoutMs: Long = 90_000,
        pollMs: Long = 500,
    ) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (!kotlin.coroutines.coroutineContext.isActive) {
                throw IOException("DNSCrypt server wait cancelled")
            }
            if (process?.isAlive != true) {
                throw IOException("DNSCrypt process exited before upstream was ready")
            }
            if (serverReady.get()) {
                Timber.i("DNSCrypt upstream server ready")
                return
            }
            // Successful A query proves an upstream is usable.
            if (probeResolvesExample(listenPort ?: return)) {
                serverReady.set(true)
                Timber.i("DNSCrypt upstream ready (DNS probe)")
                return
            }
            delay(pollMs)
        }
        throw IOException("DNSCrypt upstream server timed out (SafeSocks/proxy?)")
    }

    private fun probeResolvesExample(port: Int): Boolean {
        return try {
            DatagramSocket().use { socket ->
                socket.soTimeout = 3_000
                val query = byteArrayOf(
                    0x00, 0x02,
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
                socket.send(
                    DatagramPacket(
                        query,
                        query.size,
                        InetAddress.getByName(TunnelEndpoints.LOOPBACK),
                        port,
                    ),
                )
                val response = DatagramPacket(ByteArray(512), 512)
                socket.receive(response)
                // RCODE == 0 and at least one answer.
                response.length > 12 &&
                    (responseBufRcode(response.data) == 0) &&
                    (((response.data[6].toInt() and 0xff) shl 8) or (response.data[7].toInt() and 0xff)) > 0
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun responseBufRcode(data: ByteArray): Int = data[3].toInt() and 0x0f

    private suspend fun waitForListener(
        port: Int,
        timeoutMs: Long = 60_000,
        pollMs: Long = 250,
    ) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (!kotlin.coroutines.coroutineContext.isActive) {
                throw IOException("DNSCrypt listener wait cancelled")
            }
            if (process?.isAlive != true) {
                throw IOException("DNSCrypt process exited before listener was ready")
            }
            if (listenerReady.get() || probeLocalDns(port) || probeLocalTcp(port)) return
            delay(pollMs)
        }
        throw IOException("DNSCrypt listener timed out on port $port")
    }

    private fun probeLocalTcp(port: Int): Boolean {
        return try {
            java.net.Socket().use { socket ->
                socket.connect(
                    java.net.InetSocketAddress(
                        TunnelEndpoints.LOOPBACK,
                        port,
                    ),
                    1_000,
                )
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun probeLocalDns(port: Int): Boolean {
        return try {
            DatagramSocket().use { socket ->
                socket.soTimeout = 1_000
                val query = byteArrayOf(
                    0x00, 0x01,
                    0x01, 0x00,
                    0x00, 0x01,
                    0x00, 0x00,
                    0x00, 0x00,
                    0x00, 0x00,
                    0x03, 'w'.code.toByte(), 'w'.code.toByte(), 'w'.code.toByte(),
                    0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
                    'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
                    0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
                    0x00,
                    0x00, 0x01,
                    0x00, 0x01,
                )
                socket.send(
                    DatagramPacket(
                        query,
                        query.size,
                        InetAddress.getByName(TunnelEndpoints.LOOPBACK),
                        port,
                    ),
                )
                val response = DatagramPacket(ByteArray(512), 512)
                socket.receive(response)
                response.length > 0
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun ensureExecutable(file: File) {
        if (!file.exists()) {
            throw IOException("Binary missing at ${file.absolutePath}")
        }
        if (!file.canExecute()) {
            file.setExecutable(true, false)
        }
    }

    private fun writeConfig(serverName: String, ports: TunnelRuntimePorts) {
        configFile.writeText(
            DnsCryptConfigWriter.write(
                configDirectory = configDirectory.absolutePath,
                serverName = serverName,
                listenPort = ports.dnsCryptListenPort,
                torSocksPort = ports.torSocksPort,
                torDnsPort = ports.torDnsPort,
                preferences = preferences,
            ),
        )
        File(configDirectory, DnsCryptConfigWriter.BLOCKED_NAMES_FILE).writeText(
            DnsCryptConfigWriter.blockedNamesFileContent(),
        )
    }

    companion object {
        const val LOG_TAG = "dnscrypt"
    }

    private fun stopInternal() {
        process?.destroyForcibly()
        runCatching { process?.waitFor() }
        process = null
        logThread?.interrupt()
        logThread = null
        listenPort = null
    }

    private fun killOrphanedProcesses() {
        runCatching {
            Runtime.getRuntime()
                .exec(arrayOf("sh", "-c", "pkill -f ${binaryFile.name} 2>/dev/null || true"))
                .waitFor()
        }
    }
}
