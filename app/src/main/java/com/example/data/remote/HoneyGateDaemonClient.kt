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
  val activeConnections: Int = 0,
  val totalConnections: Int = 0,
  val isolatedCount: Int = 0,
  val rateLimitViolations: Int = 0,
  val bytesInTotal: Long = 0L,
  val bytesOutTotal: Long = 0L,
  val errorMessage: String? = null
)

data class DaemonSession(
  val fd: Int,
  val ip: String,
  val port: Int,
  val mac: String,
  val durationSec: Long,
  val outboundRateMin: Int,
  val bytesIn: Long,
  val bytesOut: Long
)

data class DaemonAlert(
  val title: String,
  val message: String,
  val severity: String,
  val date: String
)

class HoneyGateDaemonClient {

  /**
   * Consulta el estado de salud del Daemon en Linux (GET /api/status) enviando X-Auth-Token.
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
        val reader = BufferedReader(InputStreamReader(connection.inputStream))
        val body = reader.readText()
        reader.close()

        val json = JSONObject(body)
        val stats = json.optJSONObject("stats") ?: JSONObject()
        val activeSessions = json.optJSONArray("active_sessions") ?: JSONArray()
        val isolatedIps = json.optJSONObject("isolated_ips") ?: JSONObject()
        val latency = System.currentTimeMillis() - start

        DaemonStatus(
          online = true,
          hostUrl = cleanUrl,
          latencyMs = latency,
          activeConnections = activeSessions.length(),
          totalConnections = stats.optInt("total_connections", 0),
          isolatedCount = isolatedIps.length(),
          rateLimitViolations = stats.optInt("rate_limit_violations", 0),
          bytesInTotal = stats.optLong("bytes_in_total", 0L),
          bytesOutTotal = stats.optLong("bytes_out_total", 0L)
        )
      } else if (code == 401) {
        DaemonStatus(
          online = false,
          hostUrl = cleanUrl,
          errorMessage = "401 No Autorizado: Cabecera X-Auth-Token inválida"
        )
      } else {
        DaemonStatus(
          online = false,
          hostUrl = cleanUrl,
          errorMessage = "HTTP Error $code"
        )
      }
    } catch (e: Exception) {
      DaemonStatus(
        online = false,
        hostUrl = cleanUrl,
        errorMessage = e.localizedMessage ?: "No se pudo conectar al Daemon"
      )
    } finally {
      connection?.disconnect()
    }
  }

  /**
   * Obtiene la lista de conexiones activas desde el kernel Linux (GET /api/connections) enviando X-Auth-Token.
   */
  suspend fun getActiveSessions(baseUrl: String, token: String): Result<List<DaemonSession>> = withContext(Dispatchers.IO) {
    if (token.isBlank()) {
      return@withContext Result.failure(Exception("Configurá el token"))
    }
    val cleanUrl = baseUrl.trimEnd('/')
    var connection: HttpURLConnection? = null
    try {
      val url = URL("$cleanUrl/api/connections")
      connection = (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "GET"
        connectTimeout = 3000
        readTimeout = 3000
        setRequestProperty("Accept", "application/json")
        setRequestProperty("X-Auth-Token", token)
      }

      val code = connection.responseCode
      if (code == 200) {
        val reader = BufferedReader(InputStreamReader(connection.inputStream))
        val body = reader.readText()
        reader.close()

        val array = JSONArray(body)
        val list = mutableListOf<DaemonSession>()
        for (i in 0 until array.length()) {
          val item = array.getJSONObject(i)
          list.add(
            DaemonSession(
              fd = item.optInt("fd", 0),
              ip = item.optString("ip", ""),
              port = item.optInt("port", 0),
              mac = item.optString("mac", "00:00:00:00:00:00"),
              durationSec = item.optLong("duration_sec", 0L),
              outboundRateMin = item.optInt("outbound_rate_min", 0),
              bytesIn = item.optLong("bytes_in", 0L),
              bytesOut = item.optLong("bytes_out", 0L)
            )
          )
        }
        Result.success(list)
      } else if (code == 401) {
        Result.failure(Exception("401 No Autorizado: Cabecera X-Auth-Token inválida"))
      } else {
        Result.failure(Exception("HTTP $code al consultar sesiones"))
      }
    } catch (e: Exception) {
      Result.failure(e)
    } finally {
      connection?.disconnect()
    }
  }

  /**
   * Obtiene alertas forenses capturadas por inotify (GET /api/alerts) enviando X-Auth-Token.
   */
  suspend fun getAlerts(baseUrl: String, token: String): Result<List<DaemonAlert>> = withContext(Dispatchers.IO) {
    if (token.isBlank()) {
      return@withContext Result.failure(Exception("Configurá el token"))
    }
    val cleanUrl = baseUrl.trimEnd('/')
    var connection: HttpURLConnection? = null
    try {
      val url = URL("$cleanUrl/api/alerts")
      connection = (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "GET"
        connectTimeout = 3000
        readTimeout = 3000
        setRequestProperty("Accept", "application/json")
        setRequestProperty("X-Auth-Token", token)
      }

      val code = connection.responseCode
      if (code == 200) {
        val reader = BufferedReader(InputStreamReader(connection.inputStream))
        val body = reader.readText()
        reader.close()

        val array = JSONArray(body)
        val list = mutableListOf<DaemonAlert>()
        for (i in 0 until array.length()) {
          val item = array.getJSONObject(i)
          list.add(
            DaemonAlert(
              title = item.optString("title", "Alerta"),
              message = item.optString("message", ""),
              severity = item.optString("severity", "normal"),
              date = item.optString("date", "")
            )
          )
        }
        Result.success(list)
      } else if (code == 401) {
        Result.failure(Exception("401 No Autorizado: Cabecera X-Auth-Token inválida"))
      } else {
        Result.failure(Exception("HTTP $code al consultar alertas"))
      }
    } catch (e: Exception) {
      Result.failure(e)
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

      val writer = OutputStreamWriter(connection.outputStream)
      writer.write(payload.toString())
      writer.flush()
      writer.close()

      val code = connection.responseCode
      if (code == 200) {
        Result.success("IP $ip aislada físicamente en el kernel Linux (shutdown ejecutado)")
      } else if (code == 401) {
        Result.failure(Exception("401 No Autorizado: Cabecera X-Auth-Token inválida"))
      } else {
        Result.failure(Exception("HTTP $code al aislar IP $ip"))
      }
    } catch (e: Exception) {
      Result.failure(e)
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

      val payload = JSONObject().apply {
        put("ip", ip)
      }

      val writer = OutputStreamWriter(connection.outputStream)
      writer.write(payload.toString())
      writer.flush()
      writer.close()

      val code = connection.responseCode
      if (code == 200) {
        Result.success("IP $ip desbloqueada satisfactoriamente en el Daemon")
      } else if (code == 401) {
        Result.failure(Exception("401 No Autorizado: Cabecera X-Auth-Token inválida"))
      } else {
        Result.failure(Exception("HTTP $code al desbloquear IP $ip"))
      }
    } catch (e: Exception) {
      Result.failure(e)
    } finally {
      connection?.disconnect()
    }
  }
}
