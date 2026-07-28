package ltechnologies.onionphone.onionvpn.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val BrandGreen = Color(0xFF1B4332)
private val BrandGreenLight = Color(0xFF2D6A4F)
private val BrandSurface = Color(0xFFF7F9F8)
private val BrandOnSurface = Color(0xFF0F1A16)

private val LightColors = lightColorScheme(
    primary = BrandGreen,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD8F3DC),
    onPrimaryContainer = BrandGreen,
    secondary = BrandGreenLight,
    onSecondary = Color.White,
    surface = BrandSurface,
    onSurface = BrandOnSurface,
    surfaceVariant = Color(0xFFE8EEEA),
    onSurfaceVariant = Color(0xFF3D4F47),
    error = Color(0xFFB3261E),
    onError = Color.White,
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF95D5B2),
    onPrimary = BrandGreen,
    primaryContainer = BrandGreenLight,
    onPrimaryContainer = Color.White,
    secondary = Color(0xFFB7E4C7),
    onSecondary = BrandGreen,
    surface = Color(0xFF121A16),
    onSurface = Color(0xFFE8F5EE),
    surfaceVariant = Color(0xFF243029),
    onSurfaceVariant = Color(0xFFBFD8CB),
    error = Color(0xFFF2B8B5),
    onError = Color(0xFF601410),
)

@Composable
fun OnionVpnTheme(
    darkTheme: Boolean = false,
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        content = content,
    )
}
