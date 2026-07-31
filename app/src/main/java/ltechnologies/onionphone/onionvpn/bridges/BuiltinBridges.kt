package ltechnologies.onionphone.onionvpn.bridges

import android.content.Context
import org.json.JSONObject

/**
 * Built-in Tor Browser bridge presets shipped in [assets/pt_bridges.json]
 * (obfs4 / snowflake / meek). Used by Settings chips; ClientTransportPlugin
 * binaries are wired automatically by [TorBridgeConfig].
 */
object BuiltinBridges {
    const val PRESET_OFF = "off"
    const val PRESET_OBFS4 = "obfs4"
    const val PRESET_SNOWFLAKE = "snowflake"
    const val PRESET_MEEK = "meek"
    const val PRESET_CUSTOM = "custom"

    fun load(context: Context): Map<String, List<String>> {
        val text = context.assets.open("pt_bridges.json").bufferedReader().use { it.readText() }
        val root = JSONObject(text)
        val bridges = root.getJSONObject("bridges")
        return buildMap {
            bridges.keys().forEach { key ->
                val arr = bridges.getJSONArray(key)
                put(
                    key,
                    buildList {
                        for (i in 0 until arr.length()) add(arr.getString(i))
                    },
                )
            }
        }
    }

    fun linesForPreset(context: Context, preset: String): String {
        if (preset == PRESET_OFF || preset == PRESET_CUSTOM) return ""
        val all = load(context)
        return all[preset]?.joinToString("\n").orEmpty()
    }

    /** Detect which preset [bridgeText] matches (exact multiline), else custom/off. */
    fun detectPreset(context: Context, bridgeText: String): String {
        val normalized = bridgeText.trim()
        if (normalized.isEmpty()) return PRESET_OFF
        val all = load(context)
        for ((key, lines) in all) {
            if (lines.joinToString("\n").trim() == normalized) return key
        }
        return PRESET_CUSTOM
    }
}
