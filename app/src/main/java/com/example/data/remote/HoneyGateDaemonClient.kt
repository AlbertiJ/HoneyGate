package com.example.data.remote

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

data class DaemonStatus(
  val online: Boolean,
  val hostUrl: String,
  val latencyMs: Long = 0L,
  val mode: Int = 1,
  val activeConnections: Int = 0,
  val totalConnections: Int = 0,
  val isolatedCount: Int = 0,
  val rateLimitViolations: Int = 0,
  val bytesInTotal: Long = 0L,
  val bytesOutTotal: Long = 0L,
  val errorMessage: String? = null
)

data class DaemonConfigDto(
  val mode: Int,
  val retentionDays: Int,
  val maxOutboundPerMinute: Int,
  val portalEnabled: Boolean,
  val honeypotEnabled: Boolean,
  val egressWhitelist: List<String>,
  val sybilMaxEmailsPerDevice: Int,
  val sybilWindowSeconds: Int,
  val updatedAt: Double
)

data class DaemonConfigUpdate(
  val mode: Int? = null,
  val retentionDays: Int? = null,
  val maxOutboundPerMinute: Int? = null,
  val portalEnabled: Boolean? = null,
  val honeypotEnabled: Boolean? = null,
  val egressWhitelist: List<String>? = null,
  val sybilMaxEmailsPerDevice: Int? = null,
  val sybilWindowSeconds: Int? = null
) {
  fun toJson(): JSONObject = JSONObject().apply {
    mode?.let { put("mode", it) }
    retentionDays?.let { put("retention_days", it) }
    maxOutboundPerMinute?.let { put("max_outbound_per_minute", it) }
    portalEnabled?.let { put("portal_enabled", it) }
    honeypotEnabled?.let { put("honeypot_enabled", it) }
    egressWhitelist?.let { put("egress_whitelist", JSONArray(it)) }
    sybilMaxEmailsPerDevice?.let { put("sybil_max_emails_per_device", it) }
    sybilWindowSeconds?.let { put("sybil_window_seconds", it) }
  }
}

data class DaemonSessionDto(
  val id: Long,
  val mode: Int,
  val deviceId: String,
  val mac: String,
  val ip: String,
  val clientPort: Int,
  val deviceType: String,
  val browserFingerprint: String,
  val networkFingerprint: String,
  val dhcpFingerprint: String,
  val destIp: String,
  val destPort: Int,
  val service: String,
  val honeytokenTouched: String?,
  val startedAt: Double,
  val endedAt: Double?,
  val durationSec: Double,
  val status: String,
  val bytesIn: Long,
  val bytesOut: Long,
  val observedReason: String?,
  val visitorLabel: String?
)

data class DaemonSessionsPage(
  val sessions: List<DaemonSessionDto>,
  val total: Int,
  val limit: Int,
  val offset: Int
)

data class DaemonEventDto(
  val id: Long,
  val sessionId: Long?,
  val timestamp: Double,
  val createdAt: String,
  val mode: Int,
  val deviceId: String?,
  val ip: String?,
  val eventType: String,
  val severity: String,
  val mitreTechnique: String?,
  val description: String,
  val metadataMac: String?,
  val metadataHoneytoken: String?,
  val metadataTarget: String?
)

data class DaemonEventsPage(
  val events: List<DaemonEventDto>,
  val total: Int,
  val limit: Int,
  val offset: Int
)

class HoneyGateDaemonClient {

  companion object {
    private fun JSONObject.optStringOrEmpty(key: String): String {
      return if (!has(key) || isNull(key)) "" else optString(key, "")
    }

    private fun JSONObject.optStringOrNull(key: String): String? {
      if (!has(key) || isNull(key)) return null
      return optString(key, "").takeIf { it.isNotEmpty() }
    }

    private fun JSONObject.optLongOrNull(key: String): Long? {
      return if (!has(key) || isNull(key)) null else optLong(key)
    }

    private fun JSONObject.optDoubleOrNull(key: String): Double? {
      return if (!has(key) || isNull(key)) null else optDouble(key)
    }

    fun parseConfigJson(jsonText: String): DaemonConfigDto {
      val obj = JSONObject(jsonText)
      val wlArray = obj.optJSONArray("egress_whitelist") ?: JSONArray()
      val whitelist = buildList {
        for (i in 0 until wlArray.length()) {
          val item = wlArray.optString(i, "").trim()
          if (item.isNotEmpty()) add(item)
        }
      }
      return DaemonConfigDto(
        mode = obj.optInt("mode", 1),
        retentionDays = obj.optInt("retention_days", 30),
        maxOutboundPerMinute = obj.optInt("max_outbound_per_minute", 10),
        portalEnabled = obj.optBoolean("portal_enabled", true),
        honeypotEnabled = obj.optBoolean("honeypot_enabled", false),
        egressWhitelist = whitelist,
        sybilMaxEmailsPerDevice = obj.optInt("sybil_max_emails_per_device", 3),
        sybilWindowSeconds = obj.optInt("sybil_window_seconds", 600),
        updatedAt = obj.optDouble("updated_at", 0.0)
      )
    }

    fun parseSessionObject(item: JSONObject): DaemonSessionDto {
      val origin = item.optJSONObject("origin") ?: JSONObject()
      val fingerprints = origin.optJSONObject("fingerprints") ?: JSONObject()
      val target = item.optJSONObject("target") ?: JSONObject()
      val sessionObj = item.optJSONObject("session") ?: JSONObject()

      return DaemonSessionDto(
        id = item.optLong("id", 0L),
        mode = item.optInt("mode", 1),
        deviceId = origin.optStringOrEmpty("device_id").ifEmpty { item.optStringOrEmpty("device_id") },
        mac = origin.optStringOrEmpty("mac").ifEmpty { item.optStringOrEmpty("mac") },
        ip = origin.optStringOrEmpty("ip").ifEmpty { item.optStringOrEmpty("ip") },
        clientPort = origin.optInt("client_port", 0),
        deviceType = origin.optStringOrEmpty("device_type"),
        browserFingerprint = fingerprints.optStringOrEmpty("browser"),
        networkFingerprint = fingerprints.optStringOrEmpty("network"),
        dhcpFingerprint = fingerprints.optStringOrEmpty("dhcp"),
        destIp = target.optStringOrEmpty("dest_ip"),
        destPort = target.optInt("dest_port", item.optInt("dest_port", 0)),
        service = target.optStringOrEmpty("service").ifEmpty { item.optStringOrEmpty("service") },
        honeytokenTouched = target.optStringOrNull("honeytoken_touched"),
        startedAt = sessionObj.optDouble("started_at", 0.0),
        endedAt = sessionObj.optDoubleOrNull("ended_at"),
        durationSec = sessionObj.optDouble("duration_sec", item.optDouble("duration_sec", 0.0)),
        status = sessionObj.optStringOrEmpty("status").ifEmpty { item.optStringOrEmpty("status") },
        bytesIn = sessionObj.optLong("bytes_in", 0L),
        bytesOut = sessionObj.optLong("bytes_out", 0L),
        observedReason = sessionObj.optStringOrNull("observed_reason"),
        visitorLabel = item.optStringOrNull("visitor_label")
      )
    }

    fun parseSessionsPageJson(jsonText: String): DaemonSessionsPage {
      val root = JSONObject(jsonText)
      val array = root.optJSONArray("sessions") ?: JSONArray()
      val list = buildList {
        for (i in 0 until array.length()) {
          add(parseSessionObject(array.getJSONObject(i)))
        }
      }
      return DaemonSessionsPage(
        sessions = list,
        total = root.optInt("total", list.size),
        limit = root.optInt("limit", 50),
        offset = root.optInt("offset", 0)
      )
    }

    fun parseEventsPageJson(jsonText: String): DaemonEventsPage {
      val root = JSONObject(jsonText)
      val array = root.optJSONArray("events") ?: JSONArray()
      val list = buildList {
        for (i in 0 until array.length()) {
          val item = array.getJSONObject(i)
          val meta = item.optJSONObject("metadata") ?: JSONObject()
          val metaService = meta.optStringOrNull("service")
          val metaPort = if (meta.has("dest_port") && !meta.isNull("dest_port")) meta.optInt("dest_port", 0) else 0
          val targetStr = when {
            metaService != null && metaPort > 0 -> "$metaService:$metaPort"
            metaService != null -> metaService
            else -> null
          }
          add(
            DaemonEventDto(
              id = item.optLong("id", 0L),
              sessionId = item.optLongOrNull("session_id"),
              timestamp = item.optDouble("timestamp", 0.0),
              createdAt = item.optStringOrEmpty("created_at"),
              mode = item.optInt("mode", 1),
              deviceId = item.optStringOrNull("device_id"),
              ip = item.optStringOrNull("ip"),
              eventType = item.optStringOrEmpty("event_type"),
              severity = item.optStringOrEmpty("severity"),
              mitreTechnique = item.optStringOrNull("mitre_technique"),
              description = item.optStringOrEmpty("description"),
              metadataMac = meta.optStringOrNull("mac"),
              metadataHoneytoken = meta.optStringOrNull("honeytoken_touched"),
              metadataTarget = targetStr
            )
          )
        }
      }
      return DaemonEventsPage(
        events = list,
        total = root.optInt("total", list.size),
        limit = root.optInt("limit", 50),
        offset = root.optInt("offset", 0)
      )
    }
  }

  private fun readResponseBody(connection: HttpURLConnection, isError: Boolean): String {
    val stream = if (isError) connection.errorStream else connection.inputStream
    if (stream == null) return ""
    return BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).use { it.readText() }
  }

  private fun parseErrorDetail(code: Int, rawErrorBody: String, fallbackAction: String): String {
    if (code == 401) {
      return "401 No Autorizado: Cabecera X-Auth-Token inválida"
    }
    if (rawErrorBody.isNotBlank()) {
      try {
        val obj = JSONObject(rawErrorBody)
        val msg = obj.optString("error", "")
        if (msg.isNotBlank()) return "HTTP $code: $msg"
      } catch (_: Exception) {
      }
    }
    return "HTTP $code al $fallbackAction"
  }

  /**
   * Consulta el estado en vivo del Daemon (GET /api/status) enviando X-Auth-Token.
   */
  suspend fun checkHealth(baseUrl: String, token: String): DaemonStatus = withContext(Dispatchers.IO) {
    val cleanUrl = baseUrl.trimEnd('/')
    if (token.isBlank()) {
      return@withContext DaemonStatus(
        online = false,
        hostUrl = cleanUrl,
        errorMessage = "Configurá el token"
      )
    }

    val start = System.currentTimeMillis()
    var connection: HttpURLConnection? = null
    try {
      val url = URL("$cleanUrl/api/status")
      connection = (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "GET"
        connectTimeout = 3000
        readTimeout = 3000
        setRequestProperty("Accept", "application/json")
        setRequestProperty("X-Auth-Token", token)
      }

      val code = connection.responseCode
      if (code == 200) {
        val body = readResponseBody(connection, isError = false)
        val json = JSONObject(body)
        val stats = json.optJSONObject("stats") ?: JSONObject()
        val activeSessions = json.optJSONArray("active_sessions") ?: JSONArray()
        val isolatedIps = json.optJSONObject("isolated_ips") ?: JSONObject()
        val latency = System.currentTimeMillis() - start

        DaemonStatus(
          online = true,
          hostUrl = cleanUrl,
          latencyMs = latency,
          mode = json.optInt("mode", 1),
          activeConnections = activeSessions.length(),
          totalConnections = stats.optInt("total_connections", 0),
          isolatedCount = isolatedIps.length(),
          rateLimitViolations = stats.optInt("rate_limit_violations", 0),
          bytesInTotal = stats.optLong("bytes_in_total", 0L),
          bytesOutTotal = stats.optLong("bytes_out_total", 0L)
        )
      } else {
        val errBody = readResponseBody(connection, isError = true)
        DaemonStatus(
          online = false,
          hostUrl = cleanUrl,
          errorMessage = parseErrorDetail(code, errBody, "consultar /api/status")
        )
      }
    } catch (e: Exception) {
      DaemonStatus(
        online = false,
        hostUrl = cleanUrl,
        errorMessage = "Sin conexión: ${e.localizedMessage ?: "No se pudo conectar al Daemon"}"
      )
    } finally {
      connection?.disconnect()
    }
  }

  /**
   * Obtiene la configuración real persistida en SQLite del daemon (GET /api/config).
   */
  suspend fun getConfig(baseUrl: String, token: String): Result<DaemonConfigDto> = withContext(Dispatchers.IO) {
    if (token.isBlank()) return@withContext Result.failure(Exception("Configurá el token"))
    val cleanUrl = baseUrl.trimEnd('/')
    var connection: HttpURLConnection? = null
    try {
      val url = URL("$cleanUrl/api/config")
      connection = (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "GET"
        connectTimeout = 3000
        readTimeout = 3000
        setRequestProperty("Accept", "application/json")
        setRequestProperty("X-Auth-Token", token)
      }
      val code = connection.responseCode
      if (code == 200) {
        Result.success(parseConfigJson(readResponseBody(connection, isError = false)))
      } else {
        Result.failure(Exception(parseErrorDetail(code, readResponseBody(connection, isError = true), "leer configuración")))
      }
    } catch (e: Exception) {
      Result.failure(Exception("Sin conexión: ${e.localizedMessage ?: "error de red"}"))
    } finally {
      connection?.disconnect()
    }
  }

  /**
   * Actualiza la configuración real en el daemon SQLite (PUT /api/config).
   */
  suspend fun updateConfig(
    baseUrl: String,
    token: String,
    update: DaemonConfigUpdate
  ): Result<DaemonConfigDto> = withContext(Dispatchers.IO) {
    if (token.isBlank()) return@withContext Result.failure(Exception("Configurá el token"))
    val cleanUrl = baseUrl.trimEnd('/')
    var connection: HttpURLConnection? = null
    try {
      val url = URL("$cleanUrl/api/config")
      connection = (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "PUT"
        connectTimeout = 3500
        readTimeout = 3500
        doOutput = true
        setRequestProperty("Content-Type", "application/json")
        setRequestProperty("Accept", "application/json")
        setRequestProperty("X-Auth-Token", token)
      }
      OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use {
        it.write(update.toJson().toString())
        it.flush()
      }
      val code = connection.responseCode
      if (code == 200) {
        Result.success(parseConfigJson(readResponseBody(connection, isError = false)))
      } else {
        Result.failure(Exception(parseErrorDetail(code, readResponseBody(connection, isError = true), "actualizar configuración")))
      }
    } catch (e: Exception) {
      Result.failure(Exception("Sin conexión: ${e.localizedMessage ?: "error de red"}"))
    } finally {
      connection?.disconnect()
    }
  }

  /**
   * Obtiene sesiones persistidas desde SQLite del daemon (GET /api/sessions?limit=...&offset=...).
   */
  suspend fun getSessions(
    baseUrl: String,
    token: String,
    limit: Int = 50,
    offset: Int = 0
  ): Result<DaemonSessionsPage> = withContext(Dispatchers.IO) {
    if (token.isBlank()) return@withContext Result.failure(Exception("Configurá el token"))
    val cleanUrl = baseUrl.trimEnd('/')
    var connection: HttpURLConnection? = null
    try {
      val url = URL("$cleanUrl/api/sessions?limit=$limit&offset=$offset")
      connection = (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "GET"
        connectTimeout = 3000
        readTimeout = 3000
        setRequestProperty("Accept", "application/json")
        setRequestProperty("X-Auth-Token", token)
      }
      val code = connection.responseCode
      if (code == 200) {
        Result.success(parseSessionsPageJson(readResponseBody(connection, isError = false)))
      } else {
        Result.failure(Exception(parseErrorDetail(code, readResponseBody(connection, isError = true), "consultar sesiones")))
      }
    } catch (e: Exception) {
      Result.failure(Exception("Sin conexión: ${e.localizedMessage ?: "error de red"}"))
    } finally {
      connection?.disconnect()
    }
  }

  /**
   * Obtiene eventos persistidos desde SQLite del daemon (GET /api/events?limit=...&offset=...).
   */
  suspend fun getEvents(
    baseUrl: String,
    token: String,
    limit: Int = 50,
    offset: Int = 0
  ): Result<DaemonEventsPage> = withContext(Dispatchers.IO) {
    if (token.isBlank()) return@withContext Result.failure(Exception("Configurá el token"))
    val cleanUrl = baseUrl.trimEnd('/')
    var connection: HttpURLConnection? = null
    try {
      val url = URL("$cleanUrl/api/events?limit=$limit&offset=$offset")
      connection = (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "GET"
        connectTimeout = 3000
        readTimeout = 3000
        setRequestProperty("Accept", "application/json")
        setRequestProperty("X-Auth-Token", token)
      }
      val code = connection.responseCode
      if (code == 200) {
        Result.success(parseEventsPageJson(readResponseBody(connection, isError = false)))
      } else {
        Result.failure(Exception(parseErrorDetail(code, readResponseBody(connection, isError = true), "consultar eventos")))
      }
    } catch (e: Exception) {
      Result.failure(Exception("Sin conexión: ${e.localizedMessage ?: "error de red"}"))
    } finally {
      connection?.disconnect()
    }
  }

  /**
   * Marca una sesión real en observación en el daemon (POST /api/sessions/{id}/observe).
   */
  suspend fun observeSession(
    baseUrl: String,
    token: String,
    sessionId: Long,
    reason: String = "Marcada en observación desde app HoneyGate"
  ): Result<DaemonSessionDto> = withContext(Dispatchers.IO) {
    if (token.isBlank()) return@withContext Result.failure(Exception("Configurá el token"))
    val cleanUrl = baseUrl.trimEnd('/')
    var connection: HttpURLConnection? = null
    try {
      val url = URL("$cleanUrl/api/sessions/$sessionId/observe")
      connection = (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        connectTimeout = 3500
        readTimeout = 3500
        doOutput = true
        setRequestProperty("Content-Type", "application/json")
        setRequestProperty("Accept", "application/json")
        setRequestProperty("X-Auth-Token", token)
      }
      val payload = JSONObject().apply { put("reason", reason) }
      OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use {
        it.write(payload.toString())
        it.flush()
      }
      val code = connection.responseCode
      if (code == 200) {
        val root = JSONObject(readResponseBody(connection, isError = false))
        Result.success(parseSessionObject(root.getJSONObject("session")))
      } else {
        Result.failure(Exception(parseErrorDetail(code, readResponseBody(connection, isError = true), "observar sesión #$sessionId")))
      }
    } catch (e: Exception) {
      Result.failure(Exception("Sin conexión: ${e.localizedMessage ?: "error de red"}"))
    } finally {
      connection?.disconnect()
    }
  }

  /**
   * Ejecuta aislamiento perimetral remoto en Linux con X-Auth-Token (POST /api/isolate).
   */
  suspend fun remoteIsolate(
    baseUrl: String,
    token: String,
    ip: String,
    reason: String = "Aislamiento manual ordenado desde HoneyGate Android"
  ): Result<String> = withContext(Dispatchers.IO) {
    if (token.isBlank()) {
      return@withContext Result.failure(Exception("Configurá el token"))
    }
    val cleanUrl = baseUrl.trimEnd('/')
    var connection: HttpURLConnection? = null
    try {
      val url = URL("$cleanUrl/api/isolate")
      connection = (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        connectTimeout = 3500
        readTimeout = 3500
        doOutput = true
        setRequestProperty("Content-Type", "application/json")
        setRequestProperty("X-Auth-Token", token)
      }

      val payload = JSONObject().apply {
        put("ip", ip)
        put("reason", reason)
      }

      OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use {
        it.write(payload.toString())
        it.flush()
      }

      val code = connection.responseCode
      if (code == 200) {
        Result.success("IP $ip aislada en el daemon")
      } else {
        Result.failure(Exception(parseErrorDetail(code, readResponseBody(connection, isError = true), "aislar IP $ip")))
      }
    } catch (e: Exception) {
      Result.failure(Exception("Sin conexión: ${e.localizedMessage ?: "error de red"}"))
    } finally {
      connection?.disconnect()
    }
  }

  /**
   * Remueve el aislamiento perimetral de una IP (POST /api/unblock).
   */
  suspend fun remoteUnblock(
    baseUrl: String,
    token: String,
    ip: String
  ): Result<String> = withContext(Dispatchers.IO) {
    if (token.isBlank()) {
      return@withContext Result.failure(Exception("Configurá el token"))
    }
    val cleanUrl = baseUrl.trimEnd('/')
    var connection: HttpURLConnection? = null
    try {
      val url = URL("$cleanUrl/api/unblock")
      connection = (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        connectTimeout = 3500
        readTimeout = 3500
        doOutput = true
        setRequestProperty("Content-Type", "application/json")
        setRequestProperty("X-Auth-Token", token)
      }

      val payload = JSONObject().apply { put("ip", ip) }
      OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use {
        it.write(payload.toString())
        it.flush()
      }

      val code = connection.responseCode
      if (code == 200) {
        Result.success("IP $ip desbloqueada en el daemon")
      } else {
        Result.failure(Exception(parseErrorDetail(code, readResponseBody(connection, isError = true), "desbloquear IP $ip")))
      }
    } catch (e: Exception) {
      Result.failure(Exception("Sin conexión: ${e.localizedMessage ?: "error de red"}"))
    } finally {
      connection?.disconnect()
    }
  }
}
