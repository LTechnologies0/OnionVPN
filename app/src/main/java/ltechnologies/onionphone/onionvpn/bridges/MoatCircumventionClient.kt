package ltechnologies.onionphone.onionvpn.bridges

import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.validation.path.TorSocksDns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import timber.log.Timber

/**
 * Tor Project Moat **circumvention settings** client (rdsys / BridgeDB).
 *
 * Default path: clearnet HTTPS to `bridges.torproject.org`.
 * Optional path: Tor SOCKS5h (same pattern as GeoIP / ExitIpValidator).
 *
 * @see <a href="https://gitlab.torproject.org/tpo/anti-censorship/rdsys/-/blob/main/doc/moat.md">Moat API</a>
 */
object MoatCircumventionClient {
    private const val BASE = "https://bridges.torproject.org/moat/circumvention/"
    private val JSON = "application/json; charset=utf-8".toMediaType()

    data class BridgeSetting(
        val type: String,
        val source: String,
        val bridgeStrings: List<String>,
    )

    data class Result(
        val settings: List<BridgeSetting>,
        val country: String?,
        val fromDefaults: Boolean,
    )

    /**
     * @param transports preferred PTs (obfs4 / snowflake / webtunnel)
     * @param country ISO-3166-1 alpha-2 override; null = server geolocation
     * @param viaTor when true, [socksPort] must be a live Tor SocksPort
     */
    suspend fun fetchSettings(
        transports: List<String> = listOf("obfs4", "snowflake", "webtunnel"),
        country: String? = null,
        viaTor: Boolean = false,
        socksPort: Int? = null,
    ): Result = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("transports", JSONArray(transports))
            if (!country.isNullOrBlank()) put("country", country.trim().lowercase())
        }.toString()
        val client = httpClient(viaTor, socksPort)
        val primary = postJson(client, BASE + "settings", body)
        val parsed = parseResponse(primary)
        if (parsed.settings.isNotEmpty()) {
            return@withContext parsed.copy(fromDefaults = false)
        }
        Timber.i("Moat settings empty (country=%s) — trying defaults", parsed.country)
        val defaults = postJson(client, BASE + "defaults", body)
        parseResponse(defaults).copy(fromDefaults = true, country = parsed.country ?: parseResponse(defaults).country)
    }

    /** Prefer [preferredType] lines; otherwise first non-empty setting. */
    fun pickLines(result: Result, preferredType: String?): List<String> {
        val want = preferredType?.trim()?.lowercase().orEmpty()
        if (want.isNotEmpty()) {
            result.settings.firstOrNull { it.type.equals(want, ignoreCase = true) && it.bridgeStrings.isNotEmpty() }
                ?.let { return it.bridgeStrings }
        }
        return result.settings.firstOrNull { it.bridgeStrings.isNotEmpty() }?.bridgeStrings.orEmpty()
    }

    private fun httpClient(viaTor: Boolean, socksPort: Int?): OkHttpClient {
        val b = OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .followRedirects(true)
        if (viaTor) {
            val port = socksPort?.takeIf { it > 0 }
                ?: error("Tor SOCKS not ready — connect the tunnel or disable “Request via Tor”")
            b.proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress(TunnelEndpoints.LOOPBACK, port)))
            b.dns(TorSocksDns)
        }
        return b.build()
    }

    private fun postJson(client: OkHttpClient, url: String, json: String): String {
        val req = Request.Builder()
            .url(url)
            .header("Accept", "application/json")
            .header("User-Agent", "OnionVPN/moat")
            .post(json.toRequestBody(JSON))
            .build()
        client.newCall(req).execute().use { resp ->
            val text = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) {
                error("Moat HTTP ${resp.code}: ${text.take(200)}")
            }
            return text
        }
    }

    private fun parseResponse(raw: String): Result {
        val root = JSONObject(raw)
        if (root.has("errors")) {
            val err = root.optJSONArray("errors")?.optJSONObject(0)
            val detail = err?.optString("detail").orEmpty().ifBlank {
                err?.optString("code") ?: "Moat error"
            }
            error(detail)
        }
        val country = root.optString("country").ifBlank { null }
        val arr = root.optJSONArray("settings") ?: JSONArray()
        val settings = buildList {
            for (i in 0 until arr.length()) {
                val bridges = arr.optJSONObject(i)?.optJSONObject("bridges") ?: continue
                val type = bridges.optString("type")
                val source = bridges.optString("source")
                val strings = bridges.optJSONArray("bridge_strings") ?: JSONArray()
                val lines = buildList {
                    for (j in 0 until strings.length()) {
                        val line = strings.optString(j).trim()
                        if (line.isNotEmpty()) add(line)
                    }
                }
                if (type.isNotBlank() && lines.isNotEmpty()) {
                    add(BridgeSetting(type = type, source = source, bridgeStrings = lines))
                }
            }
        }
        return Result(settings = settings, country = country, fromDefaults = false)
    }
}
