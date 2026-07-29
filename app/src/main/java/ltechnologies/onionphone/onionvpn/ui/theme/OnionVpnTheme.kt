package ltechnologies.onionphone.onionvpn.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat

/** Tor / privacy brand — deep forest with mint accents (M3 Expressive contrast). */
private val Forest = Color(0xFF1B4332)
private val ForestMid = Color(0xFF2D6A4F)
private val Mint = Color(0xFF95D5B2)
private val MintBright = Color(0xFFB7E4C7)
private val LeafContainer = Color(0xFFD8F3DC)
private val Mist = Color(0xFFF4F7F5)
private val Ink = Color(0xFF0F1A16)
private val Night = Color(0xFF0C1410)
private val NightElevated = Color(0xFF16211C)
private val NightVariant = Color(0xFF243029)

private val LightColors = lightColorScheme(
    primary = Forest,
    onPrimary = Color.White,
    primaryContainer = LeafContainer,
    onPrimaryContainer = Forest,
    secondary = ForestMid,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFCDE7D6),
    onSecondaryContainer = Forest,
    tertiary = Color(0xFF3D5A80),
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFD6E4F5),
    onTertiaryContainer = Color(0xFF1B2A41),
    background = Mist,
    onBackground = Ink,
    surface = Mist,
    onSurface = Ink,
    surfaceVariant = Color(0xFFE4EBE6),
    onSurfaceVariant = Color(0xFF3D4F47),
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color(0xFFEEF3F0),
    surfaceContainer = Color(0xFFE8EEEA),
    surfaceContainerHigh = Color(0xFFE2E9E4),
    surfaceContainerHighest = Color(0xFFDCE4DF),
    outline = Color(0xFF6B7C74),
    outlineVariant = Color(0xFFBCC9C1),
    error = Color(0xFFB3261E),
    onError = Color.White,
    errorContainer = Color(0xFFF9DEDC),
    onErrorContainer = Color(0xFF410E0B),
    inverseSurface = Night,
    inverseOnSurface = Color(0xFFE8F5EE),
    inversePrimary = Mint,
)

private val DarkColors = darkColorScheme(
    primary = Mint,
    onPrimary = Forest,
    primaryContainer = ForestMid,
    onPrimaryContainer = MintBright,
    secondary = MintBright,
    onSecondary = Forest,
    secondaryContainer = Color(0xFF1E3A2E),
    onSecondaryContainer = MintBright,
    tertiary = Color(0xFFA8C5E8),
    onTertiary = Color(0xFF0F1F33),
    tertiaryContainer = Color(0xFF2A4060),
    onTertiaryContainer = Color(0xFFD6E4F5),
    background = Night,
    onBackground = Color(0xFFE8F5EE),
    surface = Night,
    onSurface = Color(0xFFE8F5EE),
    surfaceVariant = NightVariant,
    onSurfaceVariant = Color(0xFFBFD8CB),
    surfaceContainerLowest = Color(0xFF080E0B),
    surfaceContainerLow = NightElevated,
    surfaceContainer = Color(0xFF1A2520),
    surfaceContainerHigh = Color(0xFF1F2C26),
    surfaceContainerHighest = NightVariant,
    outline = Color(0xFF87998F),
    outlineVariant = Color(0xFF3A4A42),
    error = Color(0xFFF2B8B5),
    onError = Color(0xFF601410),
    errorContainer = Color(0xFF8C1D18),
    onErrorContainer = Color(0xFFF9DEDC),
    inverseSurface = Mist,
    inverseOnSurface = Ink,
    inversePrimary = Forest,
)

/** Expressive type scale — heavier display, tighter labels (M3 Expressive hierarchy). */
private val OnionTypography = Typography(
    displayLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 52.sp,
        lineHeight = 58.sp,
        letterSpacing = (-0.5).sp,
    ),
    displayMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 40.sp,
        lineHeight = 46.sp,
        letterSpacing = (-0.25).sp,
    ),
    headlineLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 32.sp,
        lineHeight = 38.sp,
    ),
    headlineMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 26.sp,
        lineHeight = 32.sp,
    ),
    headlineSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 22.sp,
        lineHeight = 28.sp,
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp,
        lineHeight = 26.sp,
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 16.sp,
        lineHeight = 22.sp,
        letterSpacing = 0.1.sp,
    ),
    titleSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        lineHeight = 20.sp,
        letterSpacing = 0.1.sp,
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
        letterSpacing = 0.15.sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
        letterSpacing = 0.2.sp,
    ),
    bodySmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.3.sp,
    ),
    labelLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 14.sp,
        lineHeight = 20.sp,
        letterSpacing = 0.1.sp,
    ),
    labelMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 12.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.4.sp,
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.4.sp,
    ),
)

val OnionShapes = androidx.compose.material3.Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(32.dp),
)

@Composable
fun OnionVpnTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colorScheme = if (darkTheme) DarkColors else LightColors
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as? Activity)?.window ?: return@SideEffect
            window.statusBarColor = Color.Transparent.toArgb()
            window.navigationBarColor = colorScheme.surfaceContainer.toArgb()
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !darkTheme
                isAppearanceLightNavigationBars = !darkTheme
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                window.isNavigationBarContrastEnforced = false
            }
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = OnionTypography,
        shapes = OnionShapes,
        content = content,
    )
}
