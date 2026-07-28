package ltechnologies.onionphone.onionvpn.firewall

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import ltechnologies.onionphone.onionvpn.R
import ltechnologies.onionphone.onionvpn.core.model.DomainThreatCategory

/**
 * Threat colours for firewall surfaces.
 *
 * - Green = sûr (pas listé tracking/malware)
 * - Orange = tracking / pubs / télémétrie
 * - Red = malware / C2
 */
object ThreatColors {
    val Green = Color(0xFF2E7D32)
    val Orange = Color(0xFFE65100)
    val Red = Color(0xFFC62828)
}

@Composable
fun threatTextColor(category: DomainThreatCategory): Color = when (category) {
    DomainThreatCategory.MALWARE -> ThreatColors.Red
    DomainThreatCategory.TRACKING -> ThreatColors.Orange
    DomainThreatCategory.NONE -> ThreatColors.Green
}

@Composable
fun threatLabelOrNull(category: DomainThreatCategory): String? = when (category) {
    DomainThreatCategory.MALWARE -> stringResource(R.string.firewall_threat_malware)
    DomainThreatCategory.TRACKING -> stringResource(R.string.firewall_threat_tracking)
    DomainThreatCategory.NONE -> null
}

/**
 * Emoji next to the domain in the connection-request notification
 * (coloured spans are unreliable on Android OEMs).
 *
 * - 🟢 domaine sûr (pas tagué tracking/malware)
 * - 🟠 tracking / pubs / télémétrie
 * - 🔴 malware / C2
 */
fun DomainThreatCategory.notificationEmoji(): String = when (this) {
    DomainThreatCategory.NONE -> "🟢"
    DomainThreatCategory.TRACKING -> "🟠"
    DomainThreatCategory.MALWARE -> "🔴"
}
