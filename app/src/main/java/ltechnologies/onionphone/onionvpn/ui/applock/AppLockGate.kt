package ltechnologies.onionphone.onionvpn.ui.applock

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import ltechnologies.onionphone.onionvpn.security.AppLockAuthResult
import ltechnologies.onionphone.onionvpn.security.AppLockAuthenticator
import ltechnologies.onionphone.onionvpn.security.AppLockManager
import ltechnologies.onionphone.onionvpn.security.AppLockState
import ltechnologies.onionphone.onionvpn.ui.components.HeroIconBadge
import ltechnologies.onionphone.onionvpn.util.SystemSecurityIntents

@Composable
fun AppLockGate(
    appLockManager: AppLockManager,
    authenticator: AppLockAuthenticator,
    content: @Composable () -> Unit,
) {
    val state by appLockManager.state.collectAsStateWithLifecycle()
    when (state) {
        AppLockState.UNLOCKED -> content()
        AppLockState.DEVICE_INSECURE -> DeviceInsecureScreen(
            onContinue = { appLockManager.markUnlocked() },
        )
        AppLockState.LOCKED -> AppLockScreen(
            authenticator = authenticator,
            onSuccess = { appLockManager.markUnlocked() },
        )
    }
}

@Composable
private fun AppLockScreen(
    authenticator: AppLockAuthenticator,
    onSuccess: () -> Unit,
) {
    val context = LocalContext.current
    val activity = context as? FragmentActivity
    var error by remember { mutableStateOf<String?>(null) }
    var promptShown by remember { mutableStateOf(false) }

    fun launchPrompt() {
        val act = activity ?: run {
            error = "Unlock requires a FragmentActivity host"
            return
        }
        promptShown = true
        authenticator.authenticate(act) { result ->
            when (result) {
                AppLockAuthResult.Success -> onSuccess()
                AppLockAuthResult.Cancelled -> promptShown = false
                is AppLockAuthResult.Failure -> {
                    error = result.message
                    promptShown = false
                }
            }
        }
    }

    LaunchedEffect(Unit) {
        if (!promptShown) launchPrompt()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(28.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        HeroIconBadge(icon = Icons.Filled.Lock, active = true)
        Text("OnionVPN locked", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Authenticate with your device lock. The VPN tunnel keeps running in the background.",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        error?.let {
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
        }
        Spacer(modifier = Modifier.height(8.dp))
        Button(
            onClick = { launchPrompt() },
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            shape = MaterialTheme.shapes.large,
        ) {
            Icon(Icons.Filled.LockOpen, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text("Unlock")
        }
    }
}

@Composable
private fun DeviceInsecureScreen(onContinue: () -> Unit) {
    val context = LocalContext.current
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(28.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        HeroIconBadge(icon = Icons.Outlined.Shield, active = false)
        Text("No screen lock", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Set a PIN, pattern, or password in Android / GrapheneOS Settings so OnionVPN can " +
                "protect the UI. Without it, anyone with the unlocked phone can change tunnel " +
                "settings and firewall rules.",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        FilledTonalButton(
            onClick = { SystemSecurityIntents.openSecuritySettings(context) },
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            shape = MaterialTheme.shapes.large,
        ) {
            Text("Open security settings")
        }
        TextButton(onClick = onContinue) {
            Text("Continue without app lock")
        }
    }
}
