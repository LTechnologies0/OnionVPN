package ltechnologies.onionphone.onionvpn.firewall

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import ltechnologies.onionphone.onionvpn.R
import ltechnologies.onionphone.onionvpn.core.model.DomainThreatCategory

/** Shared threat colours for Compose firewall surfaces (prompt + journal). */
object ThreatColors {
    val Orange = Color(0xFFE65100)
    val Red = Color(0xFFC62828)
}

@Composable
fun threatTextColor(category: DomainThreatCategory): Color = when (category) {
    DomainThreatCategory.MALWARE -> ThreatColors.Red
    DomainThreatCategory.TRACKING -> ThreatColors.Orange
    DomainThreatCategory.NONE -> MaterialTheme.colorScheme.onSurface
}

@Composable
fun threatLabelOrNull(category: DomainThreatCategory): String? = when (category) {
    DomainThreatCategory.MALWARE -> stringResource(R.string.firewall_threat_malware)
    DomainThreatCategory.TRACKING -> stringResource(R.string.firewall_threat_tracking)
    DomainThreatCategory.NONE -> null
}

/** Notification-safe marker — coloured spans are unreliable on Android OEMs. */
fun DomainThreatCategory.notificationEmojiOrNull(): String? = when (this) {
    DomainThreatCategory.NONE -> null
    DomainThreatCategory.TRACKING -> "🟠"
    DomainThreatCategory.MALWARE -> "🔴"
}
