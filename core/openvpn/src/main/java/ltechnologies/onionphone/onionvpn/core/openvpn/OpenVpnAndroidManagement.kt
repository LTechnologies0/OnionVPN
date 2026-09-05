package ltechnologies.onionphone.onionvpn.core.openvpn

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.lang.reflect.Method
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import timber.log.Timber

/**
 * ics-openvpn / TARGET_ANDROID management peer over a filesystem unix socket.
 *
 * Handles NEED-OK (IFCONFIG, ROUTE, DNS, OPENTUN, PROTECTFD, PERSIST_TUN_ACTION) and
 * SCM_RIGHTS for tun + protect FDs. For OPENTUN we send one end of a
 * **SOCK_DGRAM** AF_UNIX socketpair so OpenVPN and OnionVPN share a
 * bidirectional IP-packet channel (Android tun FD semantics: one write = one IP
 * packet; read=outbound, write=inbound) without replacing the VpnService TUN.
 *
 * [ParcelFileDescriptor.createSocketPair] is SOCK_STREAM and coalesces frames —
 * the peer then sees garbled TCP (HTTPS RST) while keepalive BYTECOUNT still
 * looks healthy.
 */
internal class OpenVpnAndroidManagement(
    private val sockFile: File,
    private val protectSocket: (Int) -> Boolean,
    private val onDataPlaneReady: (ParcelFileDescriptor) -> Unit,
    private val onControlConnected: () -> Unit,
    /**
     * Fired when management leaves CONNECTED (RECONNECTING / WAIT / EXITING / …).
     * Caller should clear Via OVPN until CONNECTED returns; keep OPENTUN pump alive
     * across soft-restarts (`persist-tun`).
     */
    private val onControlNotReady: (String) -> Unit = {},
    private val onFatal: (String) -> Unit,
    private val authUser: String = "",
    private val authPassword: String = "",
) {
    private val running = AtomicBoolean(false)
    private var server: LocalServerSocket? = null
    private var client: LocalSocket? = null
    private var thread: Thread? = null
    private val pendingProtectFds = ConcurrentLinkedQueue<FileDescriptor>()
    private var listeningLatch = CountDownLatch(1)

    /** True after unix server is bound (OpenVPN may connect). */
    fun awaitListening(timeoutMs: Long): Boolean =
        listeningLatch.await(timeoutMs, TimeUnit.MILLISECONDS)

    fun start() {
        stop()
        listeningLatch = CountDownLatch(1)
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
        listeningLatch.countDown()
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
        // Unblock any waiter if stop raced before bind completed.
        if (listeningLatch.count > 0L) listeningLatch.countDown()
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
        if (running.get()) {
            onControlNotReady("management EOF")
        }
    }

    private fun processLine(sock: LocalSocket, line: String) {
        if (line.isEmpty()) return
        Timber.d("OVPN mgmt ← %s", line)
        when {
            line.startsWith(">HOLD:") -> writeCmd(sock, "hold release\n")
            line.startsWith(">NEED-OK:") -> handleNeedOk(sock, line.removePrefix(">NEED-OK:").trim())
            line.startsWith(">STATE:") -> handleState(line)
            line.startsWith(">PASSWORD:") -> handlePassword(sock, line)
            line.startsWith(">FATAL:") -> onFatal(line)
        }
    }

    private fun handleState(line: String) {
        // >STATE:ts,CONNECTED,...  |  >STATE:ts,AUTH_FAILED,... | RECONNECTING | …
        when {
            line.contains(",CONNECTED,") -> onControlConnected()
            line.contains(",AUTH_FAILED") -> {
                // Soft reconnect AUTH_FAILED: demote Via OVPN but do not tear the process
                // if OPENTUN is still held — OpenVPN may retry. Fatal only when never up.
                onControlNotReady("AUTH_FAILED")
                onFatal("OpenVPN AUTH_FAILED — check VPN username/password")
            }
            line.contains(",EXITING,") -> {
                onControlNotReady("EXITING")
                // auth-failure already raised a specific fatal via PASSWORD / AUTH_FAILED.
                if (!line.contains("auth-failure", ignoreCase = true)) {
                    onFatal("OpenVPN exiting")
                }
            }
            CONTROL_NOT_READY.any { line.contains(it) } -> onControlNotReady(line)
        }
    }

    private fun handlePassword(sock: LocalSocket, line: String) {
        // e.g. >PASSWORD:Need 'Auth' username/password
        //      >PASSWORD:Verification Failed: 'Auth'
        if (line.contains("Verification Failed", ignoreCase = true)) {
            onFatal("OpenVPN Auth verification failed — check username/password")
            return
        }
        if (!line.contains("Auth", ignoreCase = true)) {
            onFatal("OpenVPN password type unsupported: $line")
            return
        }
        if (authUser.isEmpty() && authPassword.isEmpty()) {
            // management-query-passwords with no Settings creds: send empty
            // (do not invent provider defaults — breaks cert-only / soft reconnect).
            Timber.i("OVPN Auth requested with empty credentials — sending empty user/pass")
            writeCmd(sock, "username \"Auth\" \"\"\n")
            writeCmd(sock, "password \"Auth\" \"\"\n")
            return
        }
        // Escape quotes in credentials for management protocol.
        fun esc(s: String) = s.replace("\\", "\\\\").replace("\"", "\\\"")
        writeCmd(sock, "username \"Auth\" \"${esc(authUser)}\"\n")
        writeCmd(sock, "password \"Auth\" \"${esc(authPassword)}\"\n")
    }

    private fun handleNeedOk(sock: LocalSocket, argument: String) {
        // ics-openvpn: Need 'IFCONFIG' confirmation MSG:10.8.0.2 …
        // also tolerate bare: IFCONFIG 10.8.0.2 … / OPENTUN tun
        val (needed, extra) = parseNeedOkArgument(argument)
        when (needed) {
            "PROTECTFD" -> {
                val fd = pendingProtectFds.poll()
                val ok = if (fd != null) {
                    val fdInt = reflectGetInt(fd)
                    if (fdInt >= 0) {
                        protectSocket(fdInt).also { protected ->
                            Timber.i("OVPN PROTECTFD fd=%d ok=%s", fdInt, protected)
                        }
                    } else {
                        Timber.w("OVPN PROTECTFD invalid ancillary fd")
                        false
                    }
                } else {
                    Timber.w("OVPN PROTECTFD with no ancillary fd")
                    false
                }
                writeCmd(
                    sock,
                    if (ok) "needok 'PROTECTFD' ok\n" else "needok 'PROTECTFD' cancel\n",
                )
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
            // IFCONFIG still sets OvpnIpNat so ALLOW_OVPN packets SNAT to the
            // OpenVPN-assigned client IP (VpnService stays 10.8.0.2).
            "IFCONFIG" -> {
                OvpnIpNat.setFromIfconfigMsg(extra)
                writeCmd(sock, "needok 'IFCONFIG' ok\n")
            }
            "IFCONFIG6", "ROUTE", "ROUTE6",
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
            // Packet-oriented duplex (same as hev↔TunDnsMux): VpnService TUN and
            // TARGET_ANDROID openvpn both expect one IP frame per read/write.
            val pair = createPacketSocketPair()
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
            Timber.i("OVPN OPENTUN SOCK_DGRAM socketpair sent (packet TUN semantics)")
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
            // OPSEC: never log Auth username/password management lines (credentials).
            val trimmed = cmd.trim()
            val logSafe = when {
                trimmed.startsWith("username ", ignoreCase = true) ||
                    trimmed.startsWith("password ", ignoreCase = true) ->
                    trimmed.substringBefore(' ') + " \"…\" (redacted)"
                else -> trimmed
            }
            Timber.d("OVPN mgmt → %s", logSafe)
            sock.outputStream.write(cmd.toByteArray())
            sock.outputStream.flush()
        } catch (e: Exception) {
            Timber.w(e, "OVPN mgmt write failed")
        }
    }

    companion object {
        private var setIntMethod: Method? = null
        private var getIntMethod: Method? = null

        /**
         * AF_UNIX SOCK_DGRAM pair — one datagram = one IP packet (VpnService TUN / openvpn).
         * Large buffers so TLS bursts are not silently dropped when the pump lags.
         */
        fun createPacketSocketPair(): Array<ParcelFileDescriptor> {
            val fd0 = FileDescriptor()
            val fd1 = FileDescriptor()
            try {
                Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_DGRAM, 0, fd0, fd1)
            } catch (error: ErrnoException) {
                throw IllegalStateException(
                    "OVPN OPENTUN socketpair failed errno=${error.errno}: ${error.message}",
                    error,
                )
            }
            var left: ParcelFileDescriptor? = null
            var right: ParcelFileDescriptor? = null
            try {
                runCatching {
                    val buf = 4 * 1024 * 1024
                    Os.setsockoptInt(fd0, OsConstants.SOL_SOCKET, OsConstants.SO_SNDBUF, buf)
                    Os.setsockoptInt(fd0, OsConstants.SOL_SOCKET, OsConstants.SO_RCVBUF, buf)
                    Os.setsockoptInt(fd1, OsConstants.SOL_SOCKET, OsConstants.SO_SNDBUF, buf)
                    Os.setsockoptInt(fd1, OsConstants.SOL_SOCKET, OsConstants.SO_RCVBUF, buf)
                }
                left = ParcelFileDescriptor.dup(fd0)
                right = ParcelFileDescriptor.dup(fd1)
                runCatching { Os.close(fd0) }
                runCatching { Os.close(fd1) }
                return arrayOf(left, right)
            } catch (error: Throwable) {
                runCatching { left?.close() }
                runCatching { right?.close() }
                runCatching { Os.close(fd0) }
                runCatching { Os.close(fd1) }
                throw IllegalStateException(
                    "OVPN OPENTUN socketpair wrap failed: ${error.message}",
                    error,
                )
            }
        }

        /** Management states that mean control channel is not usable for Via OVPN. */
        private val CONTROL_NOT_READY = listOf(
            ",RECONNECTING,",
            ",WAIT,",
            ",CONNECTING,",
            ",RESOLVE,",
            ",TCP_CONNECT,",
            ",GET_CONFIG,",
            ",ASSIGN_IP,",
            ",ADD_ROUTES,",
        )

        private val NEED_OK_ICS = Regex(
            """^Need\s+'([^']+)'\s+confirmation(?:\s+MSG:(.*))?$""",
            RegexOption.IGNORE_CASE,
        )

        /**
         * Parse management NEED-OK payload after `>NEED-OK:`.
         * @return type (e.g. IFCONFIG) and MSG/extra body
         */
        fun parseNeedOkArgument(argument: String): Pair<String, String> {
            val trimmed = argument.trim()
            NEED_OK_ICS.matchEntire(trimmed)?.let { m ->
                return m.groupValues[1] to m.groupValues[2].trim()
            }
            // Fallback: first token is type (legacy / bare OpenVPN)
            val parts = trimmed.split(' ', limit = 2)
            val type = parts[0].trim().removeSurrounding("'")
            val rest = parts.getOrNull(1)?.trim().orEmpty()
            return type to rest.removePrefix("confirmation").trim()
                .removePrefix("MSG:").trim()
        }

        /** True if management STATE line means CONNECTED. */
        fun isConnectedState(line: String): Boolean = line.contains(",CONNECTED,")

        /** True if STATE line means control is down / reconnecting (not CONNECTED). */
        fun isControlNotReadyState(line: String): Boolean =
            !isConnectedState(line) &&
                (line.contains(",AUTH_FAILED") ||
                    line.contains(",EXITING,") ||
                    CONTROL_NOT_READY.any { line.contains(it) })

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
                    if (!OvpnIpNat.dnatInbound(buf, n)) continue
                    if (inboundLogBudget.getAndDecrement() > 0) {
                        // OPSEC: never log packet src IPs from SNAT/DNAT frames.
                        Timber.i("OVPN DNAT inject len=%d", n)
                    }
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
        // Copy before SNAT — TunDnsMux may reuse the read buffer for the next packet.
        val frame = packet.copyOf(length)
        if (!OvpnIpNat.snatOutbound(frame, length)) {
            Timber.v("OVPN outbound skipped — IP NAT not ready or non-IPv4")
            return false
        }
        return try {
            synchronized(outLock) {
                out.write(frame, 0, length)
                out.flush()
            }
            if (outboundLogBudget.getAndDecrement() > 0) {
                // OPSEC: never log packet dst IPs from SNAT frames.
                Timber.i("OVPN SNAT write len=%d", length)
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

    companion object {
        private val outboundLogBudget = java.util.concurrent.atomic.AtomicInteger(48)
        private val inboundLogBudget = java.util.concurrent.atomic.AtomicInteger(24)
    }
}
