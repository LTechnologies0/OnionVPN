package ltechnologies.onionphone.onionvpn.core.openvpn

import android.content.Context
import android.os.ParcelFileDescriptor
import android.system.Os
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
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
 * **Control plane:** OpenVPN `socks-proxy` → Tor OPENVPN SocksPort
 * (auth omitted — ics-openvpn 2.7 VER=5 bug; isolation via dedicated SessionGroup).
 * Java RESOLVE/probe still use [TunnelEndpoints.SOCKS_OPENVPN_USER]/[TunnelEndpoints.SOCKS_OPENVPN_PASS].
 * **Data plane:** ics-openvpn unix management + OPENTUN socketpair ↔ VpnService TUN via
 * [FirewallBridge.ovpnPacketSink] / [FirewallBridge.injectToVpnTun].
 *
 * Via OVPN ([FirewallBridge.openVpnOverTorUp]) is true **iff** CONNECTED **and** OPENTUN.
 * Soft-restarts clear Via OVPN until CONNECTED returns; OPENTUN pump is kept (`persist-tun`).
 */
class OpenVpnOverTorManager(
    private val appContext: Context,
) {
    private val _status = MutableStateFlow(OpenVpnStatus())
    val status: StateFlow<OpenVpnStatus> = _status.asStateFlow()

    private val running = AtomicBoolean(false)
    private val controlConnected = AtomicBoolean(false)
    private val dataPlaneReady = AtomicBoolean(false)
    /**
     * False when the peer accepts SNAT outbound but never returns DNAT replies
     * (data blackhole). Via OVPN demotes to Tor until replies resume.
     */
    private val dataPlaneHealthy = AtomicBoolean(true)
    /** True after at least one CONNECTED this session — soft-reconnect AUTH_FAILED demotes. */
    private val everControlConnected = AtomicBoolean(false)
    /** Invalidates watchdog / log / fatal callbacks from a previous start(). */
    private val sessionId = AtomicLong(0L)
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

    /**
     * Import a raw `.ovpn`. Embedded `<auth-user-pass>` credentials are extracted and
     * stripped from the stored profile (Settings / auth file own them at connect time).
     */
    data class ImportResult(
        val ok: Boolean,
        val authUser: String = "",
        val authPassword: String = "",
        val hadEmbeddedAuth: Boolean = false,
    )

    fun importProfile(bytes: ByteArray): Boolean = importProfileDetailed(bytes).ok

    fun importProfileDetailed(bytes: ByteArray): ImportResult {
        if (bytes.isEmpty()) return ImportResult(ok = false)
        val text = bytes.toString(Charsets.UTF_8)
        val embedded = OpenVpnConfigWriter.extractAuthUserPass(text)
        val cleaned = OpenVpnConfigWriter.stripEmbeddedAuthUserPass(text)
        profileFile.writeText(cleaned)
        if (!hasProfile()) return ImportResult(ok = false)
        return ImportResult(
            ok = true,
            authUser = embedded?.username.orEmpty(),
            authPassword = embedded?.password.orEmpty(),
            hadEmbeddedAuth = embedded != null,
        )
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
     * @param authUser / [authPassword] optional OpenVPN auth-user-pass (Settings or
     *   credentials extracted from an inline `<auth-user-pass>` block at import).
     */
    fun start(
        ports: TunnelRuntimePorts,
        authUser: String = "",
        authPassword: String = "",
    ): Result<Unit> {
        stop()
        OvpnIpNat.clear()
        val sid = sessionId.incrementAndGet()
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

        probeSocksAuth(ports.torOpenVpnSocksPort)
            .getOrElse { return fail(it.message ?: "SOCKS auth probe failed", it) }

        val pinnedProfile = pinAllRemotesViaTor(rawProfile, ports.torOpenVpnSocksPort)
            .getOrElse { return fail(it.message ?: "remote resolve via Tor failed", it) }

        val authFile = File(profileDir, "socks-auth.txt")
        // Standard OpenVPN: materialize auth-user-pass file when Settings/import
        // provided credentials. Otherwise rely on management-query-passwords Auth
        // (empty reply if still unset — never invent provider-specific defaults).
        val userPassFile = if (authUser.isNotEmpty() || authPassword.isNotEmpty()) {
            File(profileDir, "auth-user-pass.txt").also {
                it.writeText("${authUser}\n${authPassword}\n")
            }
        } else {
            File(profileDir, "auth-user-pass.txt").delete()
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
        controlConnected.set(false)
        dataPlaneReady.set(false)
        dataPlaneHealthy.set(true)
        everControlConnected.set(false)

        val mgmt = OpenVpnAndroidManagement(
            sockFile = managementSockFile,
            protectSocket = protect,
            onDataPlaneReady = { fd ->
                if (!isCurrentSession(sid)) {
                    runCatching { fd.close() }
                    return@OpenVpnAndroidManagement
                }
                attachDataPlaneTun(fd)
            },
            onControlConnected = {
                if (!isCurrentSession(sid)) return@OpenVpnAndroidManagement
                everControlConnected.set(true)
                controlConnected.set(true)
                dataPlaneHealthy.set(true)
                publishUpState("control connected via Tor SOCKS")
            },
            onControlNotReady = { reason ->
                if (!isCurrentSession(sid)) return@OpenVpnAndroidManagement
                if (controlConnected.getAndSet(false)) {
                    Timber.i("OpenVPN control not ready (%s) — Via OVPN down until CONNECTED", reason)
                    publishUpState("control not CONNECTED ($reason)")
                }
            },
            onFatal = { msg ->
                if (!isCurrentSession(sid) || !running.get()) return@OpenVpnAndroidManagement
                handleAuthOrFatal(sid, msg)
            },
            authUser = authUser,
            authPassword = authPassword,
        )
        androidMgmt = mgmt
        return try {
            mgmt.start()
            if (!mgmt.awaitListening(MGMT_LISTEN_TIMEOUT_MS)) {
                stop()
                return fail("OpenVPN management unix socket failed to listen")
            }
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
            startLogPump(proc, sid)
            startWatchdog(proc, sid)
            startDataPlaneHealthMonitor(sid)
            Timber.i(
                "OpenVPN process started binary=%s socks=:%d session=%d",
                binary.name,
                ports.torOpenVpnSocksPort,
                sid,
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
    suspend fun awaitReady(timeoutMs: Long = READY_WATCHDOG_MS): Result<Unit> {
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
            OpenVpnPhase.Error -> Result.failure(
                IllegalStateException(done.detail.ifBlank { "OpenVPN error" }),
            )
            else -> Result.failure(
                IllegalStateException("OpenVPN stopped before UP (${done.phase})"),
            )
        }
    }

    fun stop() {
        sessionId.incrementAndGet()
        val wasUp = FirewallBridge.openVpnOverTorUp
        running.set(false)
        controlConnected.set(false)
        dataPlaneReady.set(false)
        dataPlaneHealthy.set(true)
        setUpFlag(false)
        FirewallBridge.ovpnPacketSink = null
        runCatching { tunPump?.stop() }
        tunPump = null
        OvpnIpNat.clear()
        runCatching { androidMgmt?.stop() }
        androidMgmt = null
        destroyProcess(processRef.getAndSet(null))
        if (_status.value.phase != OpenVpnPhase.Idle) {
            _status.value = OpenVpnStatus(OpenVpnPhase.Idle, "stopped")
        }
        if (wasUp) {
            // already cleared via setUpFlag
        }
    }

    /**
     * Resolve every `remote` hostname over Tor SOCKS RESOLVE and pin to IPv4 so
     * OpenVPN never does clearnet DNS before the socks-proxy path.
     * Multi-remote profiles keep distinct IPs (not collapsed to a single address).
     */
    private fun pinAllRemotesViaTor(profileText: String, socksPort: Int): Result<String> {
        val hosts = OpenVpnConfigWriter.allRemoteHosts(profileText)
        if (hosts.isEmpty()) {
            return Result.failure(IllegalStateException("profile has no remote"))
        }
        var text = profileText
        val client = Socks5Client(
            proxyHost = TunnelEndpoints.LOOPBACK,
            proxyPort = socksPort,
            username = TunnelEndpoints.SOCKS_OPENVPN_USER,
            password = TunnelEndpoints.SOCKS_OPENVPN_PASS,
            connectTimeoutMs = 15_000,
            handshakeTimeoutMs = 60_000,
        )
        return try {
            for (host in hosts) {
                if (TunnelEndpoints.parseIpv4Literal(host) != null) {
                    text = OpenVpnConfigWriter.pinRemoteHostToIpv4(text, host, host)
                    continue
                }
                val addr: InetAddress = client.resolve(host)
                val ipv4 = addr.hostAddress
                    ?: return Result.failure(IllegalStateException("resolve returned no address for $host"))
                if (addr !is java.net.Inet4Address) {
                    return Result.failure(
                        IllegalStateException("Tor resolved $host to non-IPv4 ($ipv4)"),
                    )
                }
                Timber.i("OpenVPN remote %s → %s (via Tor RESOLVE)", host, ipv4)
                text = OpenVpnConfigWriter.pinRemoteHostToIpv4(text, host, ipv4)
            }
            Result.success(text)
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

    /** Fail before spawn when IsolateSOCKSAuth credentials are refused (avoids SIGUSR1 storm). */
    private fun probeSocksAuth(socksPort: Int): Result<Unit> {
        return try {
            Socks5Client(
                proxyHost = TunnelEndpoints.LOOPBACK,
                proxyPort = socksPort,
                username = TunnelEndpoints.SOCKS_OPENVPN_USER,
                password = TunnelEndpoints.SOCKS_OPENVPN_PASS,
                connectTimeoutMs = 5_000,
                handshakeTimeoutMs = 15_000,
            ).probeAuth()
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(
                IllegalStateException(
                    "OpenVPN SOCKS auth probe failed for " +
                        "${TunnelEndpoints.SOCKS_OPENVPN_USER} on :$socksPort " +
                        "(${e.message})",
                    e,
                ),
            )
        }
    }

    private fun startWatchdog(proc: Process, sid: Long) {
        thread(name = "onionvpn-ovpn-watch", isDaemon = true) {
            var waited = 0
            while (isCurrentSession(sid) && running.get() && waited < READY_WATCHDOG_MS) {
                if (!proc.isAlive) {
                    if (isCurrentSession(sid) && running.get()) {
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
            if (isCurrentSession(sid) && running.get() &&
                !(controlConnected.get() && dataPlaneReady.get())
            ) {
                val msg = when {
                    !controlConnected.get() ->
                        "OpenVPN never CONNECTED via Tor SOCKS (TCP .ovpn? auth? binary?)"
                    else ->
                        "OpenVPN CONNECTED but OPENTUN never delivered (need TARGET_ANDROID libovpnexec.so)"
                }
                Timber.w(msg)
                running.set(false)
                destroyProcess(processRef.getAndSet(null))
                runCatching { androidMgmt?.stop() }
                setUpFlag(false)
                FirewallBridge.ovpnPacketSink = null
                _status.value = OpenVpnStatus(OpenVpnPhase.Error, msg)
            }
        }
    }

    /**
     * Nested OpenVPN data plane can stay control-CONNECTED while the peer blackholes
     * TCP. Demote Via OVPN so apps fall back to Tor; restore when DNAT resumes.
     */
    private fun startDataPlaneHealthMonitor(sid: Long) {
        thread(name = "onionvpn-ovpn-health", isDaemon = true) {
            while (isCurrentSession(sid) && running.get()) {
                try {
                    Thread.sleep(DATA_PLANE_HEALTH_POLL_MS)
                } catch (_: InterruptedException) {
                    return@thread
                }
                if (!isCurrentSession(sid) || !running.get()) return@thread
                if (!controlConnected.get() || !dataPlaneReady.get()) continue
                val silent = OvpnIpNat.isDataPlaneSilent()
                val healthy = dataPlaneHealthy.get()
                when {
                    silent && healthy -> {
                        dataPlaneHealthy.set(false)
                        Timber.w(
                            "OpenVPN data plane silent (snat=%d dnat=%d) — demoting Via OVPN to Tor",
                            OvpnIpNat.snatRewriteCount,
                            OvpnIpNat.dnatRewriteCount,
                        )
                        publishUpState(
                            "OpenVPN data silent (snat=${OvpnIpNat.snatRewriteCount} " +
                                "dnat=${OvpnIpNat.dnatRewriteCount}) — using Tor",
                        )
                    }
                    !silent && !healthy -> {
                        dataPlaneHealthy.set(true)
                        Timber.i("OpenVPN data plane recovered — Via OVPN restored")
                        publishUpState("OpenVPN data plane recovered")
                    }
                }
            }
        }
    }

    private fun publishUpState(detail: String) {
        val control = controlConnected.get()
        val data = dataPlaneReady.get()
        val healthy = dataPlaneHealthy.get()
        val up = control && data && healthy
        setUpFlag(up)
        _status.value = when {
            up -> OpenVpnStatus(OpenVpnPhase.Up, detail)
            control && data && !healthy -> OpenVpnStatus(
                OpenVpnPhase.Up,
                detail,
            )
            control && !data -> OpenVpnStatus(
                OpenVpnPhase.Starting,
                "$detail — waiting for OPENTUN FD",
            )
            data && !control -> OpenVpnStatus(
                OpenVpnPhase.Starting,
                "$detail — waiting for CONNECTED",
            )
            else -> OpenVpnStatus(OpenVpnPhase.Starting, detail)
        }
        if (up) {
            Timber.i("OpenVPN-over-Tor UP (control+data+healthy)")
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

    private fun startLogPump(proc: Process, sid: Long) {
        thread(name = "onionvpn-ovpn-log", isDaemon = true) {
            var socksAuthRefusals = 0
            var socksUnexpectedAuth = 0
            try {
                proc.inputStream.bufferedReader().useLines { lines ->
                    lines.forEach { line ->
                        if (!isCurrentSession(sid)) return@useLines
                        Timber.i("openvpn: %s", line)
                        when {
                            line.contains("socks_username_password_auth: server refused") -> {
                                socksAuthRefusals++
                                if (socksAuthRefusals >= SOCKS_AUTH_REFUSAL_ABORT) {
                                    abortSocksAuthFailure(proc, sid)
                                }
                            }
                            line.contains("socks_handshake: Socks proxy returned unexpected auth") ||
                                line.contains("SIGUSR1[soft,socks-error]") -> {
                                socksUnexpectedAuth++
                                if (socksUnexpectedAuth >= SOCKS_UNEXPECTED_AUTH_ABORT) {
                                    abortSocksUnexpectedAuth(proc, sid)
                                }
                            }
                            line.contains("AUTH_FAILED") ->
                                handleAuthOrFatal(sid, "OpenVPN AUTH_FAILED (VPN credentials)")
                        }
                    }
                }
            } catch (_: Exception) {
            }
        }
    }

    /**
     * Soft reconnect after connection-reset often AUTH_FAILs when credentials do not
     * match that attempt. If we already had CONNECTED+OPENTUN, demote Via OVPN and keep
     * the process alive for another soft retry — do not kill the Tor path.
     */
    private fun handleAuthOrFatal(sid: Long, msg: String) {
        if (!isCurrentSession(sid) || !running.get()) return
        val authLike = msg.contains("AUTH", ignoreCase = true) ||
            msg.contains("Auth", ignoreCase = true) ||
            msg.contains("password", ignoreCase = true)
        if (authLike && everControlConnected.get() && dataPlaneReady.get()) {
            Timber.w("OpenVPN %s after prior CONNECTED — demoting Via OVPN, keeping process", msg)
            controlConnected.set(false)
            dataPlaneHealthy.set(false)
            setUpFlag(false)
            _status.value = OpenVpnStatus(
                OpenVpnPhase.Starting,
                "$msg — soft reconnect (Via OVPN demoted)",
            )
            return
        }
        abortFatal(processRef.get() ?: return, sid, msg)
    }

    /** Stop reconnect storm when Tor/onionmasq SOCKS rejects OpenVPN credentials. */
    private fun abortSocksAuthFailure(proc: Process, sid: Long) {
        abortFatal(
            proc,
            sid,
            "OpenVPN SOCKS auth refused — ics-openvpn 2.7 expects RFC1929 VER=5 " +
                "(Tor sends VER=1); OnionVPN omits socks-proxy authfile for this reason",
        )
    }

    /**
     * Arti IsolateSOCKSAuth rejects OpenVPN's NO-AUTH greeting when the role mux
     * falls back to a transparent relay. Fail-closed instead of a 120s socks-error storm.
     */
    private fun abortSocksUnexpectedAuth(proc: Process, sid: Long) {
        abortFatal(
            proc,
            sid,
            "OpenVPN SOCKS unexpected auth — Arti requires IsolateSOCKSAuth; " +
                "SocksAuthInjectingRelay must terminate NO-AUTH and inject uopenvpn/popenvpn",
        )
    }

    private fun abortFatal(proc: Process, sid: Long, msg: String) {
        if (!isCurrentSession(sid) || !running.get()) return
        Timber.e(msg)
        running.set(false)
        destroyProcess(processRef.getAndSet(null))
        runCatching { proc.destroy() }
        runCatching { androidMgmt?.stop() }
        setUpFlag(false)
        FirewallBridge.ovpnPacketSink = null
        _status.value = OpenVpnStatus(OpenVpnPhase.Error, msg)
    }

    private fun destroyProcess(proc: Process?) {
        if (proc == null) return
        runCatching { proc.destroy() }
        // Give soft destroy a moment; then force (zombie / stuck SOCKS).
        thread(name = "onionvpn-ovpn-kill", isDaemon = true) {
            try {
                Thread.sleep(PROCESS_DESTROY_GRACE_MS)
                if (proc.isAlive) {
                    Timber.w("OpenVPN still alive after destroy — destroyForcibly")
                    runCatching { proc.destroyForcibly() }
                }
            } catch (_: InterruptedException) {
            }
        }
    }

    private fun isCurrentSession(sid: Long): Boolean = sessionId.get() == sid

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

    companion object {
        /** Abort reconnect storm after this many SOCKS username/password refusals. */
        private const val SOCKS_AUTH_REFUSAL_ABORT = 3
        /** Abort after repeated Arti "unexpected auth" / soft socks-error (shim regression). */
        private const val SOCKS_UNEXPECTED_AUTH_ABORT = 5
        /** Match awaitReady / Tor SOCKS + TLS hand-window budget. */
        const val READY_WATCHDOG_MS = 120_000L
        private const val MGMT_LISTEN_TIMEOUT_MS = 5_000L
        private const val PROCESS_DESTROY_GRACE_MS = 1_500L
        private const val DATA_PLANE_HEALTH_POLL_MS = 5_000L
    }
}
