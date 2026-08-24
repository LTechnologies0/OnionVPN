package ltechnologies.onionphone.onionvpn.core.openvpn

import android.content.Context
import android.os.ParcelFileDescriptor
import android.system.Os
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.FirewallBridge
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.OvpnPacketSink
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.Socks5Client
import timber.log.Timber

/**
 * Optional OpenVPN-over-Tor client: TCP OpenVPN reaches the VPN server via Tor SOCKS
 * (SessionGroup OPENVPN).
 *
 * **Control plane:** OpenVPN `socks-proxy` → Tor OPENVPN SocksPort (auth openvpn/overtor).
 * **Data plane:** ics-openvpn unix management + OPENTUN sends one end of a socketpair to
 * OpenVPN; we keep the other end and pump IP frames ↔ VpnService TUN via
 * [FirewallBridge.ovpnPacketSink] / [FirewallBridge.injectToVpnTun].
 *
 * Works for both C Tor (native SocksPort) and Arti (role-mux / onionmasq sidecar).
 * Requires TARGET_ANDROID `libovpnexec.so` (ics-openvpn) in the app native library dir.
 */
class OpenVpnOverTorManager(
    private val appContext: Context,
) {
    private val _status = MutableStateFlow(OpenVpnStatus())
    val status: StateFlow<OpenVpnStatus> = _status.asStateFlow()

    private val running = AtomicBoolean(false)
    private val controlConnected = AtomicBoolean(false)
    private val dataPlaneReady = AtomicBoolean(false)
    private val processRef = AtomicReference<Process?>(null)
    private var androidMgmt: OpenVpnAndroidManagement? = null
    private var tunPump: OpenVpnTunPump? = null

    /**
     * Protect OpenVPN's uplink sockets from the VpnService TUN (PROTECTFD).
     * Loopback SOCKS does not need protect; non-loopback would.
     * Set by [TunnelForegroundService] from [android.net.VpnService.protect].
     */
    @Volatile
    var protectSocket: ((Int) -> Boolean)? = null

    /**
     * Fired when [FirewallBridge.openVpnOverTorUp] flips (true = Via OVPN available).
     * Wire to refresh firewall prompt notifications.
     */
    @Volatile
    var onUpChanged: ((Boolean) -> Unit)? = null

    private val profileDir: File
        get() = File(appContext.filesDir, "openvpn").also { it.mkdirs() }

    val profileFile: File
        get() = File(profileDir, "profile.ovpn")

    val runtimeConfigFile: File
        get() = File(profileDir, "runtime.ovpn")

    private val managementSockFile: File
        get() = File(profileDir, "mgmt.sock")

    fun importProfile(bytes: ByteArray): Boolean {
        if (bytes.isEmpty()) return false
        profileFile.writeBytes(bytes)
        return hasProfile()
    }

    fun clearProfile() {
        profileFile.delete()
        runtimeConfigFile.delete()
        File(profileDir, "socks-auth.txt").delete()
        File(profileDir, "auth-user-pass.txt").delete()
        managementSockFile.delete()
    }

    fun hasProfile(): Boolean = profileFile.isFile && profileFile.length() > 0L

    /**
     * Attach OpenVPN data-plane end of the OPENTUN socketpair and publish Via OVPN when
     * control is also CONNECTED.
     */
    fun attachDataPlaneTun(tunFd: ParcelFileDescriptor) {
        runCatching { tunPump?.stop() }
        val pump = OpenVpnTunPump(tunFd) { packet, n ->
            val inject = FirewallBridge.injectToVpnTun
            if (inject != null) {
                inject(packet.copyOf(n), n)
            } else {
                Timber.w("OVPN inbound dropped — VpnService TUN inject not wired")
            }
        }
        tunPump = pump
        pump.start()
        FirewallBridge.ovpnPacketSink = OvpnPacketSink { packet, length ->
            pump.offerOutbound(packet, length)
        }
        dataPlaneReady.set(true)
        publishUpState("data plane attached (OPENTUN socketpair)")
        Timber.i("OpenVPN-over-Tor data plane attached")
    }

    /**
     * @param ports must include [TunnelRuntimePorts.torOpenVpnSocksPort]
     * @param authUser / [authPassword] optional OpenVPN auth-user-pass (VPN Gate: vpn/vpn)
     */
    fun start(
        ports: TunnelRuntimePorts,
        authUser: String = "",
        authPassword: String = "",
    ): Result<Unit> {
        stop()
        if (!hasProfile()) {
            return fail("OpenVPN profile missing")
        }
        val binary = resolveBinary()
            ?: return fail(
                "libovpnexec.so missing or not executable — " +
                    "reinstall APK / run native/openvpn/fetch-ics-openvpn-libs.sh",
            )

        val protect = protectSocket ?: { _ ->
            Timber.w("OpenVPN protectSocket not wired — PROTECTFD may fail for non-loopback")
            true
        }

        val rawProfile = profileFile.readText()
        if (OpenVpnConfigWriter.looksUdpOnly(rawProfile)) {
            return fail(
                "Profile looks UDP-only — OpenVPN-over-Tor needs a TCP .ovpn " +
                    "(Tor SOCKS cannot carry UDP)",
            )
        }

        if (!waitForOpenVpnSocks(ports.torOpenVpnSocksPort)) {
            return fail(
                "Tor OpenVPN SocksPort :${ports.torOpenVpnSocksPort} not accepting " +
                    "(C Tor SocksPort / Arti role-mux not ready)",
            )
        }

        val pinnedProfile = pinRemoteViaTor(rawProfile, ports.torOpenVpnSocksPort)
            .getOrElse { return fail(it.message ?: "remote resolve via Tor failed", it) }

        val authFile = File(profileDir, "socks-auth.txt")
        val userPassFile = if (authUser.isNotEmpty() || authPassword.isNotEmpty()) {
            File(profileDir, "auth-user-pass.txt").also {
                it.writeText("$authUser\n$authPassword\n")
            }
        } else {
            null
        }
        val rewritten = OpenVpnConfigWriter.rewrite(
            profileText = pinnedProfile,
            socksPort = ports.torOpenVpnSocksPort,
            managementSockPath = managementSockFile.absolutePath,
            socksAuthFile = authFile,
            authUserPassFile = userPassFile,
        )
        OpenVpnConfigWriter.writeTo(runtimeConfigFile, rewritten)

        _status.value = OpenVpnStatus(OpenVpnPhase.Starting, "starting openvpn management")
        running.set(true)

        val mgmt = OpenVpnAndroidManagement(
            sockFile = managementSockFile,
            protectSocket = protect,
            onDataPlaneReady = { fd -> attachDataPlaneTun(fd) },
            onControlConnected = {
                controlConnected.set(true)
                publishUpState("control connected via Tor SOCKS")
            },
            onFatal = { msg ->
                Timber.w("OpenVPN fatal: %s", msg)
                if (running.get()) {
                    running.set(false)
                    processRef.getAndSet(null)?.destroy()
                    setUpFlag(false)
                    FirewallBridge.ovpnPacketSink = null
                    _status.value = OpenVpnStatus(OpenVpnPhase.Error, msg)
                }
            },
            authUser = authUser,
            authPassword = authPassword,
        )
        androidMgmt = mgmt
        return try {
            mgmt.start()
            // Brief window so the unix server is bound before OpenVPN connects.
            Thread.sleep(80)
            val libDir = File(appContext.applicationInfo.nativeLibraryDir)
            val pb = ProcessBuilder(
                binary.absolutePath,
                "--config",
                runtimeConfigFile.absolutePath,
            ).directory(profileDir)
                .redirectErrorStream(true)
            // libovpnexec.so NEEDED libopenvpn.so — linker must search nativeLibraryDir.
            val env = pb.environment()
            val existing = env["LD_LIBRARY_PATH"]
            env["LD_LIBRARY_PATH"] = if (existing.isNullOrBlank()) {
                libDir.absolutePath
            } else {
                "${libDir.absolutePath}:$existing"
            }
            val proc = pb.start()
            processRef.set(proc)
            startLogPump(proc)
            startWatchdog(proc)
            Timber.i(
                "OpenVPN process started binary=%s socks=:%d",
                binary.name,
                ports.torOpenVpnSocksPort,
            )
            Result.success(Unit)
        } catch (e: Exception) {
            stop()
            fail(e.message ?: "OpenVPN start failed", e)
        }
    }

    /**
     * Wait until control CONNECTED + OPENTUN data plane, or [timeoutMs] / Error.
     * Call after a successful [start] so Via OVPN is live before firewall prompts.
     */
    suspend fun awaitReady(timeoutMs: Long = 90_000L): Result<Unit> {
        val done = withTimeoutOrNull(timeoutMs) {
            status.first {
                it.phase == OpenVpnPhase.Up ||
                    it.phase == OpenVpnPhase.Error ||
                    it.phase == OpenVpnPhase.Idle
            }
        } ?: return Result.failure(
            IllegalStateException("OpenVPN-over-Tor timed out waiting for CONNECTED+OPENTUN"),
        )
        return when (done.phase) {
            OpenVpnPhase.Up -> Result.success(Unit)
            OpenVpnPhase.Error -> Result.failure(IllegalStateException(done.detail.ifBlank { "OpenVPN error" }))
            else -> Result.failure(IllegalStateException("OpenVPN stopped before UP (${done.phase})"))
        }
    }

    fun stop() {
        val wasUp = FirewallBridge.openVpnOverTorUp
        running.set(false)
        controlConnected.set(false)
        dataPlaneReady.set(false)
        setUpFlag(false)
        FirewallBridge.ovpnPacketSink = null
        runCatching { tunPump?.stop() }
        tunPump = null
        runCatching { androidMgmt?.stop() }
        androidMgmt = null
        processRef.getAndSet(null)?.destroy()
        if (_status.value.phase != OpenVpnPhase.Idle) {
            _status.value = OpenVpnStatus(OpenVpnPhase.Idle, "stopped")
        }
        if (wasUp) {
            // already cleared via setUpFlag
        }
    }

    /**
     * Resolve VPN server hostname over Tor SOCKS RESOLVE and pin `remote` to IPv4 so
     * OpenVPN never does clearnet DNS before the socks-proxy path.
     */
    private fun pinRemoteViaTor(profileText: String, socksPort: Int): Result<String> {
        val host = OpenVpnConfigWriter.firstRemoteHost(profileText)
            ?: return Result.failure(IllegalStateException("profile has no remote"))
        if (TunnelEndpoints.parseIpv4Literal(host) != null) {
            return Result.success(OpenVpnConfigWriter.pinRemoteToIpv4(profileText, host))
        }
        return try {
            val client = Socks5Client(
                proxyHost = TunnelEndpoints.LOOPBACK,
                proxyPort = socksPort,
                username = TunnelEndpoints.SOCKS_OPENVPN_USER,
                password = TunnelEndpoints.SOCKS_OPENVPN_PASS,
                connectTimeoutMs = 15_000,
                handshakeTimeoutMs = 60_000,
            )
            val addr: InetAddress = client.resolve(host)
            val ipv4 = addr.hostAddress
                ?: return Result.failure(IllegalStateException("resolve returned no address"))
            val v4 = if (addr is java.net.Inet4Address) {
                ipv4
            } else {
                return Result.failure(
                    IllegalStateException("Tor resolved $host to non-IPv4 ($ipv4)"),
                )
            }
            Timber.i("OpenVPN remote %s → %s (via Tor RESOLVE)", host, v4)
            Result.success(OpenVpnConfigWriter.pinRemoteToIpv4(profileText, v4))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun waitForOpenVpnSocks(port: Int, attempts: Int = 40, delayMs: Long = 250L): Boolean {
        repeat(attempts) { i ->
            val ok = runCatching {
                Socket().use { s ->
                    s.connect(InetSocketAddress(TunnelEndpoints.LOOPBACK, port), 500)
                }
            }.isSuccess
            if (ok) {
                if (i > 0) Timber.i("OpenVPN SocksPort :%d ready after %d tries", port, i + 1)
                return true
            }
            try {
                Thread.sleep(delayMs)
            } catch (_: InterruptedException) {
                return false
            }
        }
        return false
    }

    private fun startWatchdog(proc: Process) {
        thread(name = "onionvpn-ovpn-watch", isDaemon = true) {
            var waited = 0
            while (running.get() && waited < 90_000) {
                if (!proc.isAlive) {
                    if (running.get()) {
                        val msg = "OpenVPN process exited early (see openvpn: logs)"
                        Timber.w(msg)
                        setUpFlag(false)
                        FirewallBridge.ovpnPacketSink = null
                        _status.value = OpenVpnStatus(OpenVpnPhase.Error, msg)
                        running.set(false)
                    }
                    return@thread
                }
                if (controlConnected.get() && dataPlaneReady.get()) return@thread
                Thread.sleep(500)
                waited += 500
            }
            if (running.get() && !(controlConnected.get() && dataPlaneReady.get())) {
                val msg = when {
                    !controlConnected.get() ->
                        "OpenVPN never CONNECTED via Tor SOCKS (TCP .ovpn? auth? binary?)"
                    else ->
                        "OpenVPN CONNECTED but OPENTUN never delivered (need TARGET_ANDROID libovpnexec.so)"
                }
                Timber.w(msg)
                running.set(false)
                processRef.getAndSet(null)?.destroy()
                runCatching { androidMgmt?.stop() }
                setUpFlag(false)
                FirewallBridge.ovpnPacketSink = null
                _status.value = OpenVpnStatus(OpenVpnPhase.Error, msg)
            }
        }
    }

    private fun publishUpState(detail: String) {
        val control = controlConnected.get()
        val data = dataPlaneReady.get()
        val up = control && data
        setUpFlag(up)
        _status.value = when {
            up -> OpenVpnStatus(OpenVpnPhase.Up, detail)
            control && !data -> OpenVpnStatus(
                OpenVpnPhase.Starting,
                "$detail — waiting for OPENTUN FD",
            )
            else -> OpenVpnStatus(OpenVpnPhase.Starting, detail)
        }
        if (up) {
            Timber.i("OpenVPN-over-Tor UP (control+data)")
        }
    }

    private fun setUpFlag(up: Boolean) {
        val prev = FirewallBridge.openVpnOverTorUp
        FirewallBridge.openVpnOverTorUp = up
        if (prev != up) {
            runCatching { onUpChanged?.invoke(up) }
                .onFailure { Timber.w(it, "onUpChanged failed") }
        }
    }

    private fun startLogPump(proc: Process) {
        thread(name = "onionvpn-ovpn-log", isDaemon = true) {
            try {
                proc.inputStream.bufferedReader().useLines { lines ->
                    lines.forEach { Timber.i("openvpn: %s", it) }
                }
            } catch (_: Exception) {
            }
        }
    }

    private fun resolveBinary(): File? {
        val dir = File(appContext.applicationInfo.nativeLibraryDir)
        val candidates = listOf(
            File(dir, "libovpnexec.so"),
            File(dir, "ovpnexec"),
        )
        for (f in candidates) {
            if (!f.isFile) continue
            ensureExecutable(f)
            if (f.canExecute() || f.isFile) return f
        }
        // Fallback: copy pie_openvpn from assets (same F-Droid package).
        val abi = android.os.Build.SUPPORTED_ABIS.firstOrNull() ?: return null
        val assetName = when {
            abi.startsWith("arm64") -> "openvpn/pie_openvpn.arm64-v8a"
            abi.startsWith("x86_64") -> "openvpn/pie_openvpn.x86_64"
            else -> return null
        }
        val out = File(profileDir, "pie_openvpn")
        return try {
            if (!out.isFile || out.length() == 0L) {
                appContext.assets.open(assetName).use { inp ->
                    out.outputStream().use { inp.copyTo(it) }
                }
            }
            ensureExecutable(out)
            out.takeIf { it.isFile }
        } catch (e: Exception) {
            Timber.w(e, "Failed to extract %s", assetName)
            null
        }
    }

    private fun ensureExecutable(file: File) {
        if (file.canExecute()) return
        runCatching {
            file.setExecutable(true, false)
            Os.chmod(file.absolutePath, 448) // 0700
        }.onFailure { Timber.d(it, "chmod %s", file.name) }
    }

    private fun fail(msg: String, cause: Throwable? = null): Result<Unit> {
        Timber.w(cause, "OpenVPN-over-Tor: %s", msg)
        _status.value = OpenVpnStatus(OpenVpnPhase.Error, msg)
        setUpFlag(false)
        FirewallBridge.ovpnPacketSink = null
        return Result.failure(cause ?: IllegalStateException(msg))
    }
}
