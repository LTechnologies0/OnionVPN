package ltechnologies.onionphone.onionvpn.bridges

import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.model.SocksJavaProxyAuth
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
 * Empty `/settings` for a country means Moat has **no special circumvention map**
 * for that location (direct Tor often works). `/defaults` still returns generic
 * lines — prefer **obfs4** / **snowflake** when ranking; webtunnel lines are kept
 * and normalized with `utls=none` at torrc time ([TorBridgeConfig]).
 *
 * @see <a href="https://gitlab.torproject.org/tpo/anti-censorship/rdsys/-/blob/main/doc/moat.md">Moat API</a>
 */
object MoatCircumventionClient {
    private const val BASE = "https://bridges.torproject.org/moat/circumvention/"
    private val JSON = "application/json; charset=utf-8".toMediaType()

    /** Prefer reliable PTs first; webtunnel last (CDN/TLS sensitive). */
    private val TRANSPORT_RANK = listOf(
        "obfs4",
        "snowflake",
        "meek",
        "meek_lite",
        "meek-azure",
        "webtunnel",
    )

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

    data class FetchOutcome(
        val lines: List<String>,
        val transport: String,
        val country: String?,
        val source: String,
        val note: String? = null,
    )

    /**
     * High-level Moat fetch for Settings UI.
     *
     * - Country `/settings` first, then `/defaults`.
     * - Prefer bridgedb over builtin within a transport.
     * - Sanitize webtunnel (require `url=`). WebTunnel TLS is fixed later via
     *   [ltechnologies.onionphone.onionvpn.core.tor.config.TorBridgeConfig.normalizeBridgeLine].
     */
    suspend fun fetchBridges(
        transport: String,
        country: String? = null,
        viaTor: Boolean = false,
        socksPort: Int? = null,
    ): FetchOutcome {
        val want = transport.trim().lowercase()
        require(want.isNotEmpty()) { "transport required" }

        val primary = fetchSettings(
            transports = listOf(want),
            country = country,
            viaTor = viaTor,
            socksPort = socksPort,
        )
        val primaryLines = pickLines(primary, want)

        if (primaryLines.isNotEmpty()) {
            return FetchOutcome(
                lines = primaryLines,
                transport = want,
                country = primary.country,
                source = if (primary.fromDefaults) "defaults" else "settings",
                note = if (want == "webtunnel") {
                    "WebTunnel lines get utls=none at apply (stdlib TLS)"
                } else {
                    null
                },
            )
        }

        if (want == "obfs4" || want == "snowflake" || want == "webtunnel") {
            val builtin = fetchBuiltin(listOf(want), viaTor, socksPort)
            if (builtin.isNotEmpty()) {
                return FetchOutcome(
                    lines = builtin,
                    transport = want,
                    country = primary.country,
                    source = "builtin",
                    note = "Moat settings/defaults empty — used /circumvention/builtin",
                )
            }
        }

        error("No $want bridges in Moat response")
    }

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
        parseResponse(defaults).copy(
            fromDefaults = true,
            country = parsed.country ?: parseResponse(defaults).country,
        )
    }

    /**
     * Prefer [preferredType] lines (bridgedb before builtin); otherwise best-ranked
     * non-empty setting. Drops invalid webtunnel lines (missing `url=`).
     */
    fun pickLines(result: Result, preferredType: String?): List<String> {
        val want = preferredType?.trim()?.lowercase().orEmpty()
        val candidates = result.settings
            .map { it.copy(bridgeStrings = sanitizeLines(it.type, it.bridgeStrings)) }
            .filter { it.bridgeStrings.isNotEmpty() }
        if (candidates.isEmpty()) return emptyList()

        if (want.isNotEmpty()) {
            val merged = rankedForType(candidates, want)
                .flatMap { it.bridgeStrings }
                .distinct()
            if (merged.isNotEmpty()) return merged.take(MAX_BRIDGE_LINES)
        }
        val bestType = candidates
            .minWith(compareBy<BridgeSetting> { transportRank(it.type) }.thenBy { sourceRank(it.source) })
            .type
        return rankedForType(candidates, bestType)
            .flatMap { it.bridgeStrings }
            .distinct()
            .take(MAX_BRIDGE_LINES)
    }

    private const val MAX_BRIDGE_LINES = 6

    /** GET `/moat/circumvention/builtin` — stable public TBA-style lines. */
    suspend fun fetchBuiltin(
        transports: List<String>,
        viaTor: Boolean = false,
        socksPort: Int? = null,
    ): List<String> = withContext(Dispatchers.IO) {
        val client = httpClient(viaTor, socksPort)
        val req = Request.Builder()
            .url(BASE + "builtin")
            .header("Accept", "application/json")
            .header("User-Agent", "OnionVPN/moat")
            .get()
            .build()
        val raw = SocksJavaProxyAuth.withProbe {
            // Clearnet Moat still fine — Authenticator unused without SOCKS challenge.
            client.newCall(req).execute().use { resp ->
                val text = resp.body?.string().orEmpty()
                if (!resp.isSuccessful) {
                    error("Moat builtin HTTP ${resp.code}: ${text.take(200)}")
                }
                text
            }
        }
        val root = JSONObject(raw)
        val want = transports.map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet()
        buildList {
            for (key in root.keys()) {
                val type = key.trim().lowercase()
                if (want.isNotEmpty() && type !in want && !(type == "meek-azure" && "meek" in want)) {
                    continue
                }
                val arr = root.optJSONArray(key) ?: continue
                val rawLines = buildList {
                    for (i in 0 until arr.length()) {
                        val line = arr.optString(i).trim()
                        if (line.isNotEmpty()) add(line)
                    }
                }
                addAll(sanitizeLines(type, rawLines))
            }
        }
    }

    private fun rankedForType(settings: List<BridgeSetting>, type: String): List<BridgeSetting> =
        settings
            .filter { it.type.equals(type, ignoreCase = true) }
            .sortedBy { sourceRank(it.source) }

    private fun transportRank(type: String): Int {
        val i = TRANSPORT_RANK.indexOf(type.trim().lowercase())
        return if (i >= 0) i else TRANSPORT_RANK.size
    }

    /** bridgedb (fresh) before builtin / unknown. */
    private fun sourceRank(source: String): Int = when (source.trim().lowercase()) {
        "bridgedb" -> 0
        "builtin" -> 1
        else -> 2
    }

    private fun sanitizeLines(type: String, lines: List<String>): List<String> {
        val t = type.trim().lowercase()
        return lines.map { it.trim() }.filter { it.isNotEmpty() }.filter { line ->
            if (t != "webtunnel" && !line.startsWith("webtunnel", ignoreCase = true)) {
                return@filter true
            }
            // WebTunnel needs the HTTPS front in url=; ORPort alone is not enough.
            line.contains("url=", ignoreCase = true)
        }
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
            // Built once per call; Authenticator scoped around each Moat HTTP exchange.
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
        return SocksJavaProxyAuth.withProbe {
            client.newCall(req).execute().use { resp ->
                val text = resp.body?.string().orEmpty()
                if (!resp.isSuccessful) {
                    error("Moat HTTP ${resp.code}: ${text.take(200)}")
                }
                text
            }
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
