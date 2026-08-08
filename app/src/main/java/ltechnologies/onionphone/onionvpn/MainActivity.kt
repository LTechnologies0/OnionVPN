package ltechnologies.onionphone.onionvpn

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.automirrored.outlined.List
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import ltechnologies.onionphone.onionvpn.OnionVpnApplication
import ltechnologies.onionphone.onionvpn.firewall.InteractiveFirewallEngine
import ltechnologies.onionphone.onionvpn.security.AppLockAuthenticator
import ltechnologies.onionphone.onionvpn.security.AppLockManager
import timber.log.Timber
import ltechnologies.onionphone.onionvpn.threat.repo.DomainReputationRepository
import ltechnologies.onionphone.onionvpn.core.model.observability.DiagnosticsGate
import ltechnologies.onionphone.onionvpn.core.tor.control.lifecycle.CircuitLifecycleManager
import ltechnologies.onionphone.onionvpn.diagnostics.ResourceSnapshot
import ltechnologies.onionphone.onionvpn.ui.FirewallScreen
import ltechnologies.onionphone.onionvpn.ui.LogsScreen
import ltechnologies.onionphone.onionvpn.ui.SettingsScreen
import ltechnologies.onionphone.onionvpn.ui.StatusScreen
import ltechnologies.onionphone.onionvpn.ui.applock.AppLockGate
import ltechnologies.onionphone.onionvpn.ui.theme.OnionVpnTheme
import ltechnologies.onionphone.onionvpn.util.BatteryOptimization
import ltechnologies.onionphone.onionvpn.util.WindowSecureHelper

@AndroidEntryPoint
class MainActivity : FragmentActivity() {
    private val viewModel: MainViewModel by viewModels()

    @Inject lateinit var firewallEngine: InteractiveFirewallEngine
    @Inject lateinit var domainReputation: DomainReputationRepository
    @Inject lateinit var appLockManager: AppLockManager
    @Inject lateinit var appLockAuthenticator: AppLockAuthenticator
    @Inject lateinit var circuitLifecycle: CircuitLifecycleManager

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            viewModel.startTunnel()
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {
        requestBatteryExemptionThenStart()
    }

    /** OnionShare-style: OS battery whitelist dialog; continue regardless of result. */
    private val batteryExemptionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) {
        launchVpnOrStart()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            OnionVpnTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    val snapshot by viewModel.snapshot.collectAsStateWithLifecycle()
                    val preferences by viewModel.preferences.collectAsStateWithLifecycle()

                    LaunchedEffect(preferences.appLockEnabled) {
                        appLockManager.enabled = preferences.appLockEnabled
                    }
                    LaunchedEffect(preferences.allowScreenshots) {
                        WindowSecureHelper.apply(this@MainActivity, preferences.allowScreenshots)
                    }
                    // Auto-start tunnel on app open (before / regardless of UI lock).
                    // Debug broadcast DEBUG_START_TUNNEL also lands here (FGS-safe foreground).
                    LaunchedEffect(Unit) {
                        val debugStart = intent?.getBooleanExtra(
                            "debug_start_tunnel",
                            false,
                        ) == true
                        val debugStop = intent?.getBooleanExtra(
                            "debug_stop_tunnel",
                            false,
                        ) == true
                        if (debugStop) {
                            appLockManager.enabled = false
                            appLockManager.markUnlocked()
                            Timber.i("debug_stop_tunnel — stopping tunnel")
                            viewModel.stopTunnel()
                        } else if (debugStart) {
                            appLockManager.enabled = false
                            appLockManager.markUnlocked()
                            val prefs = viewModel.applyDebugTunnelIntent(
                                intent?.getStringExtra("tor_engine"),
                                intent?.getStringExtra("tun_data_plane"),
                            )
                            Timber.i(
                                "debug_start_tunnel applied engine=%s plane=%s",
                                prefs.torEngine,
                                prefs.tunDataPlane,
                            )
                            requestNotificationsThenStart()
                        } else {
                            val prefs = viewModel.awaitStoredPreferences()
                            if (viewModel.shouldAutoStartTunnel(prefs)) {
                                requestNotificationsThenStart()
                            }
                        }
                    }

                    LaunchedEffect(preferences.noLogsEnabled) {
                        DiagnosticsGate.setNoLogsEnabled(preferences.noLogsEnabled)
                    }
                    val profilerFlow = remember {
                        OnionVpnApplication.profiler(application)
                            ?.snapshot
                            ?: MutableStateFlow(ResourceSnapshot()).asStateFlow()
                    }
                    val diagnosticsOn by DiagnosticsGate.diagnosticsEnabled.collectAsStateWithLifecycle()

                    AppLockGate(
                        appLockManager = appLockManager,
                        authenticator = appLockAuthenticator,
                    ) {
                        OnionVpnApp(
                            snapshot = snapshot,
                            preferences = preferences,
                            firewallEngine = firewallEngine,
                            domainReputation = domainReputation,
                            circuitLifecycle = circuitLifecycle,
                            resourceSnapshot = profilerFlow,
                            diagnosticsEnabled = diagnosticsOn,
                            onStart = ::requestNotificationsThenStart,
                            onStop = viewModel::stopTunnel,
                            onNewNym = viewModel::newNym,
                            onSavePreferences = viewModel::savePreferences,
                            onLoadTorrc = viewModel::readTorrc,
                            onLoadDnsCryptToml = viewModel::readDnsCryptToml,
                            onSaveTorrc = viewModel::saveTorrc,
                            onSaveDnsCryptToml = viewModel::saveDnsCryptToml,
                            torSocksPort = viewModel::currentTorSocksPort,
                        )
                    }
                }
            }
        }
    }

    override fun onStop() {
        // Re-lock UI when leaving foreground; tunnel keeps running.
        if (!isChangingConfigurations) {
            appLockManager.lock()
        }
        super.onStop()
    }

    private fun requestNotificationsThenStart() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        requestBatteryExemptionThenStart()
    }

    private fun requestBatteryExemptionThenStart() {
        if (BatteryOptimization.needsWhitelisting(this)) {
            try {
                batteryExemptionLauncher.launch(BatteryOptimization.requestIgnoreIntent(this))
                return
            } catch (error: ActivityNotFoundException) {
                Timber.w(error, "Battery exemption Activity missing — continue start")
            }
        }
        launchVpnOrStart()
    }

    private fun launchVpnOrStart() {
        val intent = viewModel.prepareVpnPermission(this)
        if (intent == null) {
            viewModel.startTunnel()
        } else {
            vpnPermissionLauncher.launch(intent)
        }
    }
}

@Composable
private fun OnionVpnApp(
    snapshot: ltechnologies.onionphone.onionvpn.core.model.TunnelSnapshot,
    preferences: ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences,
    firewallEngine: InteractiveFirewallEngine,
    domainReputation: DomainReputationRepository,
    circuitLifecycle: CircuitLifecycleManager,
    resourceSnapshot: StateFlow<ResourceSnapshot>,
    diagnosticsEnabled: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onNewNym: () -> Unit,
    onSavePreferences: (
        prefs: ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences,
        restartIfConnected: Boolean,
    ) -> Unit,
    onLoadTorrc: suspend () -> String,
    onLoadDnsCryptToml: suspend () -> String,
    onSaveTorrc: (String) -> Unit,
    onSaveDnsCryptToml: (String) -> Unit,
    torSocksPort: () -> Int?,
) {
    var selected by remember { mutableIntStateOf(0) }
    data class Dest(
        val label: String,
        val selectedIcon: ImageVector,
        val unselectedIcon: ImageVector,
    )
    val destinations = listOf(
        Dest("Status", Icons.Filled.Shield, Icons.Outlined.Shield),
        Dest("Firewall", Icons.Filled.Security, Icons.Outlined.Security),
        Dest("Logs", Icons.AutoMirrored.Filled.List, Icons.AutoMirrored.Outlined.List),
        Dest("Settings", Icons.Filled.Settings, Icons.Outlined.Settings),
    )

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        bottomBar = {
            NavigationBar(
                containerColor = MaterialTheme.colorScheme.surfaceContainer,
                tonalElevation = 0.dp,
            ) {
                destinations.forEachIndexed { index, dest ->
                    val selectedTab = selected == index
                    NavigationBarItem(
                        selected = selectedTab,
                        onClick = { selected = index },
                        icon = {
                            Icon(
                                imageVector = if (selectedTab) dest.selectedIcon else dest.unselectedIcon,
                                contentDescription = dest.label,
                            )
                        },
                        label = { Text(dest.label) },
                    )
                }
            }
        },
    ) { padding ->
        androidx.compose.foundation.layout.Box(modifier = Modifier.padding(padding)) {
            when (selected) {
                0 -> StatusScreen(
                    snapshot = snapshot,
                    isBusy = snapshot.isBusy,
                    onStart = onStart,
                    onStop = onStop,
                    onNewNym = onNewNym,
                    circuitLifecycle = circuitLifecycle,
                    resourceSnapshot = resourceSnapshot,
                    diagnosticsEnabled = diagnosticsEnabled,
                )
                1 -> FirewallScreen(engine = firewallEngine, preferences = preferences)
                2 -> LogsScreen()
                else -> SettingsScreen(
                    preferences = preferences,
                    domainReputation = domainReputation,
                    onLoadTorrc = onLoadTorrc,
                    onLoadDnsCryptToml = onLoadDnsCryptToml,
                    onSavePreferences = onSavePreferences,
                    onSaveTorrc = onSaveTorrc,
                    onSaveDnsCryptToml = onSaveDnsCryptToml,
                    activeEngine = if (snapshot.isActive) snapshot.torEngine else null,
                    torSocksPort = torSocksPort,
                    controlsEnabled = !snapshot.isBusy &&
                        !snapshot.identityRefreshing &&
                        snapshot.phase != ltechnologies.onionphone.onionvpn.core.model.TunnelPhase.Stopping,
                )
            }
        }
    }
}
