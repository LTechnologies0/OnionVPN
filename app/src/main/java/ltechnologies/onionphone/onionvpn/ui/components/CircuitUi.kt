package ltechnologies.onionphone.onionvpn.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import ltechnologies.onionphone.onionvpn.core.tor.control.geo.RelayCountryLookup
import java.util.Locale
import android.graphics.drawable.Drawable
import androidx.compose.foundation.Image

/**
 * Shared circuits chrome — C Tor control plane and onionmasq CircuitStore use the same layout.
 */
@Composable
fun CircuitsScreenScaffold(
    title: String,
    subtitle: String,
    onBack: () -> Unit,
    metrics: @Composable () -> Unit,
    actions: @Composable () -> Unit,
    empty: Boolean,
    emptyHint: String,
    modifier: Modifier = Modifier,
    listContent: LazyListScope.() -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
            }
            SectionHeader(
                title = title,
                subtitle = subtitle,
                modifier = Modifier.weight(1f),
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            metrics()
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            actions()
        }
        if (empty) {
            EmptyStateHint(emptyHint)
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                content = listContent,
            )
        }
    }
}

@Composable
fun AppCircuitCard(
    title: String,
    subtitle: String,
    pathText: String,
    metaText: String,
    appIcon: Drawable?,
    appContentDescription: String,
    primaryLabel: String,
    onPrimary: () -> Unit,
    secondaryLabel: String? = null,
    onSecondary: (() -> Unit)? = null,
    secondaryIcon: ImageVector? = null,
    modifier: Modifier = Modifier,
) {
    ElevatedCard(
        modifier = modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
        ),
        elevation = CardDefaults.elevatedCardElevation(defaultElevation = 0.dp),
    ) {
        Box(modifier = Modifier.fillMaxWidth()) {
            if (appIcon != null) {
                val bmp = remember(appIcon) { appIcon.toBitmap(96, 96).asImageBitmap() }
                Image(
                    bitmap = bmp,
                    contentDescription = appContentDescription,
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(12.dp)
                        .size(40.dp),
                )
            }
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                val endPad = if (appIcon != null) 48.dp else 0.dp
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(end = endPad),
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(end = endPad),
                )
                if (pathText.isNotBlank()) {
                    Text(
                        text = pathText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (metaText.isNotBlank()) {
                    Text(
                        text = metaText,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = onPrimary,
                        shape = MaterialTheme.shapes.medium,
                    ) { Text(primaryLabel) }
                    if (secondaryLabel != null && onSecondary != null) {
                        OutlinedButton(
                            onClick = onSecondary,
                            shape = MaterialTheme.shapes.medium,
                        ) {
                            if (secondaryIcon != null) {
                                Icon(
                                    secondaryIcon,
                                    contentDescription = null,
                                    modifier = Modifier.padding(end = 4.dp),
                                )
                            }
                            Text(secondaryLabel)
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun CircuitActionButton(
    label: String,
    onClick: () -> Unit,
    icon: ImageVector,
    tonal: Boolean = true,
) {
    if (tonal) {
        FilledTonalButton(onClick = onClick) {
            Icon(icon, contentDescription = null)
            Spacer(Modifier.width(6.dp))
            Text(label)
        }
    } else {
        OutlinedButton(onClick = onClick) {
            Icon(icon, contentDescription = null)
            Spacer(Modifier.width(6.dp))
            Text(label)
        }
    }
}

/** Country-code hops only — never relay IPs / fingerprints (UI safety). */
fun formatCountryHopPath(countryCodes: List<String>): String {
    if (countryCodes.isEmpty()) return ""
    return countryCodes.joinToString(" → ") { cc ->
        val flag = RelayCountryLookup.flagEmoji(cc)
        val upper = cc.uppercase(Locale.US)
        if (flag.isNotEmpty()) "$flag $upper" else upper
    }
}

fun formatByteCount(bytes: Long): String = when {
    bytes < 1_024 -> "$bytes B"
    bytes < 1_024 * 1_024 -> String.format(Locale.US, "%.1f KiB", bytes / 1024.0)
    bytes < 1_024L * 1_024 * 1_024 ->
        String.format(Locale.US, "%.1f MiB", bytes / (1024.0 * 1024.0))
    else -> String.format(Locale.US, "%.2f GiB", bytes / (1024.0 * 1024.0 * 1024.0))
}

/**
 * SOCKS IsolateSOCKSAuth username is an isolation token — show uid role, not raw string.
 * Avoids leaking internal epoch forms (`dnscrypt-n3`, `u10123-n1`) into screenshots/recents
 * when FLAG_SECURE is off.
 */
fun redactSocksAuthForUi(user: String?): String {
    if (user.isNullOrBlank()) return "—"
    return when {
        user == "dnscrypt" || user.startsWith("dnscrypt-n") -> "DNSCrypt"
        user == "probe" -> "probe"
        user == "pac" || user.startsWith("pac") -> "PAC"
        user.startsWith("u") -> {
            val uid = user.removePrefix("u").substringBefore('-').toIntOrNull()
            if (uid != null) "app uid=$uid" else "app"
        }
        else -> "isolated"
    }
}
