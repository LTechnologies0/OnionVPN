package ltechnologies.onionphone.onionvpn.core.openvpn

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.ParcelFileDescriptor
import java.io.File
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.lang.reflect.Method
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import timber.log.Timber

/**
 * ics-openvpn / TARGET_ANDROID management peer over a filesystem unix socket.
 *
 * Handles NEED-OK (IFCONFIG, ROUTE, DNS, OPENTUN, PROTECTFD, PERSIST_TUN_ACTION) and
 * SCM_RIGHTS for tun + protect FDs. For OPENTUN we send one end of a
 * [ParcelFileDescriptor.createSocketPair] so OpenVPN and OnionVPN share a
 * bidirectional IP-packet channel (Android tun FD semantics: read=outbound,
 * write=inbound) without replacing the VpnService TUN.
 */
internal class OpenVpnAndroidManagement(
    private val sockFile: File,
    private val protectSocket: (Int) -> Boolean,
    private val onDataPlaneReady: (ParcelFileDescriptor) -> Unit,
    private val onControlConnected: () -> Unit,
    private val onFatal: (String) -> Unit,
    private val authUser: String = "",
    private val authPassword: String = "",
) {
    private val running = AtomicBoolean(false)
    private var server: LocalServerSocket? = null
    private var client: LocalSocket? = null
    private var thread: Thread? = null
    private val pendingProtectFds = ConcurrentLinkedQueue<FileDescriptor>()
    fun start() {
        stop()
        sockFile.parentFile?.mkdirs()
        if (sockFile.exists()) sockFile.delete()
        val local = LocalSocket()
        local.bind(
            LocalSocketAddress(
                sockFile.absolutePath,
                LocalSocketAddress.Namespace.FILESYSTEM,
            ),
        )
        server = LocalServerSocket(local.fileDescriptor)
        running.set(true)
        thread = thread(name = "onionvpn-ovpn-mgmt", isDaemon = true) {
            try {
                val c = server!!.accept()
                client = c
                Timber.i("OpenVPN management client connected")
                pump(c)
            } catch (e: Exception) {
                if (running.get()) {
                    Timber.w(e, "OpenVPN management accept/pump failed")
                    onFatal(e.message ?: "management failed")
                }
            }
        }
    }

    fun stop() {
        running.set(false)
        runCatching { client?.shutdownInput() }
        runCatching { client?.close() }
        runCatching { server?.close() }
        client = null
        server = null
        thread?.interrupt()
        thread = null
        pendingProtectFds.clear()
        if (sockFile.exists()) sockFile.delete()
    }

    private fun pump(sock: LocalSocket) {
        val reader = sock.inputStream.bufferedReader()
        // Release hold so OpenVPN proceeds to NEED-OK / CONNECTED.
        writeCmd(sock, "hold release\n")
        writeCmd(sock, "state on\n")
        writeCmd(sock, "bytecount 5\n")
        while (running.get()) {
            val line = reader.readLine() ?: break
            // Ancillary FDs arrive with PROTECTFD on the same read.
            collectAncillaryFds(sock)
            processLine(sock, line.trim())
        }
    }

    private fun processLine(sock: LocalSocket, line: String) {
        if (line.isEmpty()) return
        Timber.d("OVPN mgmt ← %s", line)
        when {
            line.startsWith(">HOLD:") -> writeCmd(sock, "hold release\n")
            line.startsWith(">NEED-OK:") -> handleNeedOk(sock, line.removePrefix(">NEED-OK:").trim())
            line.startsWith(">STATE:") && line.contains(",CONNECTED,") -> onControlConnected()
            line.startsWith(">PASSWORD:") -> handlePassword(sock, line)
            line.startsWith(">FATAL:") -> onFatal(line)
        }
    }

    private fun handlePassword(sock: LocalSocket, line: String) {
        // e.g. >PASSWORD:Need 'Auth' username/password
        if (!line.contains("Auth", ignoreCase = true)) {
            onFatal("OpenVPN password type unsupported: $line")
            return
        }
        if (authUser.isEmpty() && authPassword.isEmpty()) {
            onFatal("OpenVPN Auth required — set username/password in Settings (VPN Gate: vpn/vpn)")
            return
        }
        // Escape quotes in credentials for management protocol.
        fun esc(s: String) = s.replace("\\", "\\\\").replace("\"", "\\\"")
        writeCmd(sock, "username \"Auth\" \"${esc(authUser)}\"\n")
        writeCmd(sock, "password \"Auth\" \"${esc(authPassword)}\"\n")
    }

    private fun handleNeedOk(sock: LocalSocket, argument: String) {
        // Formats: "OPENTUN tun" or "IFCONFIG 10.8.0.2 255.255.255.0 1500 net30"
        val parts = argument.split(' ', limit = 2)
        val needed = parts[0].trim().removeSurrounding("'")
        val extra = parts.getOrNull(1)?.trim().orEmpty()
        when (needed) {
            "PROTECTFD" -> {
                val fd = pendingProtectFds.poll()
                if (fd != null) {
                    val fdInt = reflectGetInt(fd)
                    if (fdInt >= 0) {
                        val ok = protectSocket(fdInt)
                        Timber.i("OVPN PROTECTFD fd=%d ok=%s", fdInt, ok)
                    }
                } else {
                    Timber.w("OVPN PROTECTFD with no ancillary fd")
                }
                writeCmd(sock, "needok 'PROTECTFD' ok\n")
            }
            "OPENTUN" -> {
                if (!extra.contains("tun")) {
                    writeCmd(sock, "needok 'OPENTUN' cancel\n")
                    return
                }
                if (!sendTunFd(sock)) {
                    writeCmd(sock, "needok 'OPENTUN' cancel\n")
                }
            }
            "PERSIST_TUN_ACTION" -> writeCmd(sock, "needok 'PERSIST_TUN_ACTION' OPEN_BEFORE_CLOSE\n")
            // We deliberately do not apply ROUTE/DNS to the Android VpnService —
            // OnionVPN already owns the device TUN + DNSCrypt. Ack so OpenVPN proceeds.
            "IFCONFIG", "IFCONFIG6", "ROUTE", "ROUTE6",
            "DNSSERVER", "DNS6SERVER", "DNSDOMAIN",
            -> writeCmd(sock, "needok '$needed' ok\n")
            else -> {
                Timber.w("OVPN unknown NEED-OK %s — ack", needed)
                writeCmd(sock, "needok '$needed' ok\n")
            }
        }
    }

    private fun sendTunFd(sock: LocalSocket): Boolean {
        return try {
            // Android VpnService TUN semantics (also what TARGET_ANDROID openvpn expects):
            // read = outbound IP to encapsulate, write = inbound decrypted IP.
            // A socketpair gives OpenVPN that duplex without replacing our VpnService TUN.
            val pair = ParcelFileDescriptor.createSocketPair()
            val ours = pair[0]
            val theirs = pair[1]
            val fdtosend = FileDescriptor()
            reflectSetInt(fdtosend, theirs.fd)
            sock.setFileDescriptorsForSend(arrayOf(fdtosend))
            writeCmd(sock, "needok 'OPENTUN' ok\n")
            // Prevent re-sending the same FD on every subsequent write (ics-openvpn quirk).
            sock.setFileDescriptorsForSend(null)
            // Drop our handle to `theirs`; SCM_RIGHTS already dup'd it into the message.
            runCatching { theirs.close() }
            onDataPlaneReady(ours)
            Timber.i("OVPN OPENTUN socketpair sent (Android tun FD semantics)")
            true
        } catch (e: Exception) {
            Timber.e(e, "OVPN OPENTUN failed")
            false
        }
    }

    private fun collectAncillaryFds(sock: LocalSocket) {
        try {
            val fds = sock.ancillaryFileDescriptors ?: return
            for (fd in fds) {
                if (fd != null) pendingProtectFds.add(fd)
            }
        } catch (_: Exception) {
        }
    }

    private fun writeCmd(sock: LocalSocket, cmd: String) {
        try {
            Timber.d("OVPN mgmt → %s", cmd.trim())
            sock.outputStream.write(cmd.toByteArray())
            sock.outputStream.flush()
        } catch (e: Exception) {
            Timber.w(e, "OVPN mgmt write failed")
        }
    }

    companion object {
        private var setIntMethod: Method? = null
        private var getIntMethod: Method? = null

        private fun reflectSetInt(fd: FileDescriptor, value: Int) {
            val m = setIntMethod ?: FileDescriptor::class.java
                .getDeclaredMethod("setInt$", Int::class.javaPrimitiveType)
                .also {
                    it.isAccessible = true
                    setIntMethod = it
                }
            m.invoke(fd, value)
        }

        private fun reflectGetInt(fd: FileDescriptor): Int {
            val m = getIntMethod ?: FileDescriptor::class.java
                .getDeclaredMethod("getInt$")
                .also {
                    it.isAccessible = true
                    getIntMethod = it
                }
            return m.invoke(fd) as Int
        }
    }
}

/**
 * Duplex IP frame pump between OpenVPN's private channel and callbacks.
 */
internal class OpenVpnTunPump(
    private val tun: ParcelFileDescriptor,
    private val onInbound: (ByteArray, Int) -> Unit,
) {
    private val running = AtomicBoolean(false)
    private var reader: Thread? = null
    private val out = FileOutputStream(tun.fileDescriptor)
    private val outLock = Any()

    fun start() {
        if (!running.compareAndSet(false, true)) return
        reader = thread(name = "onionvpn-ovpn-tun-rd", isDaemon = true) {
            val input = FileInputStream(tun.fileDescriptor)
            val buf = ByteArray(32767)
            try {
                while (running.get()) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    onInbound(buf, n)
                }
            } catch (_: InterruptedException) {
            } catch (e: Exception) {
                if (running.get()) Timber.w(e, "OVPN tun read stopped")
            }
        }
    }

    fun offerOutbound(packet: ByteArray, length: Int): Boolean {
        if (!running.get()) return false
        return try {
            synchronized(outLock) {
                out.write(packet, 0, length)
                out.flush()
            }
            true
        } catch (e: Exception) {
            Timber.w(e, "OVPN tun write failed")
            false
        }
    }

    fun stop() {
        running.set(false)
        reader?.interrupt()
        reader = null
        runCatching { out.close() }
        runCatching { tun.close() }
    }
}
