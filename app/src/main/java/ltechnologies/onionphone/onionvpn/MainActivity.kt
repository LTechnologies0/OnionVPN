package ltechnologies.onionphone.onionvpn

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import ltechnologies.onionphone.onionvpn.firewall.InteractiveFirewallEngine
import ltechnologies.onionphone.onionvpn.ui.FirewallScreen
import ltechnologies.onionphone.onionvpn.ui.LogsScreen
import ltechnologies.onionphone.onionvpn.ui.SettingsScreen
import ltechnologies.onionphone.onionvpn.ui.StatusScreen
import ltechnologies.onionphone.onionvpn.ui.theme.OnionVpnTheme

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()

    @Inject lateinit var firewallEngine: InteractiveFirewallEngine

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
        // Continue start regardless — FGS still works; notification may be silent if denied.
        launchVpnOrStart()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            OnionVpnTheme {
                val snapshot by viewModel.snapshot.collectAsStateWithLifecycle()
                val preferences by viewModel.preferences.collectAsStateWithLifecycle()
                OnionVpnApp(
                    snapshot = snapshot,
                    preferences = preferences,
                    firewallEngine = firewallEngine,
                    onStart = ::requestNotificationsThenStart,
                    onStop = viewModel::stopTunnel,
                    onNewNym = viewModel::newNym,
                    onSavePreferences = viewModel::savePreferences,
                    onLoadTorrc = viewModel::readTorrc,
                    onLoadDnsCryptToml = viewModel::readDnsCryptToml,
                    onSaveTorrc = viewModel::saveTorrc,
                    onSaveDnsCryptToml = viewModel::saveDnsCryptToml,
                )
            }
        }
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
    onStart: () -> Unit,
    onStop: () -> Unit,
    onNewNym: () -> Unit,
    onSavePreferences: (ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences) -> Unit,
    onLoadTorrc: () -> String,
    onLoadDnsCryptToml: () -> String,
    onSaveTorrc: (String) -> Unit,
    onSaveDnsCryptToml: (String) -> Unit,
) {
    var selected by remember { mutableIntStateOf(0) }
    val destinations = listOf("Status", "Firewall", "Logs", "Settings")

    Scaffold(
        bottomBar = {
            NavigationBar {
                destinations.forEachIndexed { index, label ->
                    NavigationBarItem(
                        selected = selected == index,
                        onClick = { selected = index },
                        icon = {
                            Icon(
                                imageVector = when (index) {
                                    0 -> Icons.Filled.Shield
                                    1 -> Icons.Filled.Security
                                    2 -> Icons.Filled.List
                                    else -> Icons.Filled.Settings
                                },
                                contentDescription = label,
                            )
                        },
                        label = { Text(label) },
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
                )
                1 -> FirewallScreen(engine = firewallEngine, preferences = preferences)
                2 -> LogsScreen()
                else -> SettingsScreen(
                    preferences = preferences,
                    onLoadTorrc = onLoadTorrc,
                    onLoadDnsCryptToml = onLoadDnsCryptToml,
                    onSavePreferences = onSavePreferences,
                    onSaveTorrc = onSaveTorrc,
                    onSaveDnsCryptToml = onSaveDnsCryptToml,
                )
            }
        }
    }
}
