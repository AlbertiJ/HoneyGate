package com.example.data.repository

import com.example.data.local.dao.ForensicEventDao
import com.example.data.local.dao.HoneygateConfigDao
import com.example.data.local.dao.MonitoredSessionDao
import com.example.data.local.entity.ForensicEvent
import com.example.data.local.entity.HoneygateConfigEntity
import com.example.data.local.entity.MonitoredSessionEntity
import com.example.data.remote.DaemonConfigDto
import com.example.data.remote.DaemonConfigUpdate
import com.example.data.remote.DaemonEventDto
import com.example.data.remote.DaemonSessionDto
import com.example.data.remote.DaemonStatus
import com.example.data.remote.HoneyGateDaemonClient
import kotlinx.coroutines.flow.Flow
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class DaemonSyncSummary(
  val message: String,
  val sessionsCount: Int,
  val sessionsTotal: Int,
  val eventsCount: Int,
  val eventsTotal: Int,
  val syncedAtMs: Long
)

class HoneyGateRepository(
  private val eventDao: ForensicEventDao,
  private val sessionDao: MonitoredSessionDao,
  private val configDao: HoneygateConfigDao
) {
  private val daemonClient = HoneyGateDaemonClient()

  val allEvents: Flow<List<ForensicEvent>> = eventDao.getAllEvents()
  val allSessions: Flow<List<MonitoredSessionEntity>> = sessionDao.getAllSessions()
  val honeygateConfig: Flow<HoneygateConfigEntity?> = configDao.getConfig()

  suspend fun insertEvent(event: ForensicEvent) = eventDao.insertEvent(event)

  suspend fun deleteEvent(id: Long) = eventDao.deleteEventById(id)

  suspend fun clearAllEvents() = eventDao.clearAll()

  suspend fun saveHoneygateConfig(config: HoneygateConfigEntity) = configDao.saveConfig(config)

  suspend fun getConfigOnce(): HoneygateConfigEntity? = configDao.getConfigOnce()

  /**
   * Inicializa únicamente la fila de configuración local si la base Room está vacía.
   * No precarga eventos ni sesiones falsas: Room actúa exclusivamente como caché del daemon.
   */
  suspend fun preseedInitialDataIfEmpty() {
    if (configDao.getConfigOnce() == null) {
      configDao.saveConfig(HoneygateConfigEntity(id = 1))
    }
  }

  /**
   * Activa o desactiva el modo DEMO explícito. Al desactivarlo, elimina toda caché marcada isDemo=true.
   */
  suspend fun setDemoMode(enabled: Boolean): HoneygateConfigEntity {
    val current = configDao.getConfigOnce() ?: HoneygateConfigEntity(id = 1)
    if (!enabled) {
      eventDao.clearByDemoFlag(true)
      sessionDao.clearByDemoFlag(true)
    }
    val updated = current.copy(demoModeEnabled = enabled)
    configDao.saveConfig(updated)
    return updated
  }

  suspend fun checkDaemonHealth(baseUrl: String, token: String): DaemonStatus {
    if (token.isBlank()) {
      return DaemonStatus(
        online = false,
        hostUrl = baseUrl.trimEnd('/'),
        errorMessage = "Configurá el token"
      )
    }
    return daemonClient.checkHealth(baseUrl, token)
  }

  /**
   * Sincroniza la caché Room contra los endpoints reales del daemon:
   * GET /api/config, GET /api/sessions?limit=...&offset=... y GET /api/events?limit=...&offset=...
   */
  suspend fun syncWithDaemon(
    baseUrl: String,
    token: String,
    limit: Int = 50,
    offset: Int = 0
  ): Result<DaemonSyncSummary> {
    if (token.isBlank()) {
      return Result.failure(Exception("Configurá el token"))
    }

    val configResult = daemonClient.getConfig(baseUrl, token)
    val sessionsResult = daemonClient.getSessions(baseUrl, token, limit = limit, offset = offset)
    val eventsResult = daemonClient.getEvents(baseUrl, token, limit = limit, offset = offset)

    val failure = listOf(configResult, sessionsResult, eventsResult).firstOrNull { it.isFailure }?.exceptionOrNull()
    if (configResult.isFailure && sessionsResult.isFailure && eventsResult.isFailure) {
      return Result.failure(failure ?: Exception("Sin conexión con el daemon"))
    }

    val syncedAt = System.currentTimeMillis()
    val currentCfg = configDao.getConfigOnce() ?: HoneygateConfigEntity(id = 1)
    var updatedCfg = currentCfg.copy(lastSyncedAtMs = syncedAt)

    configResult.onSuccess { dto ->
      updatedCfg = mergeDaemonConfig(updatedCfg, dto, syncedAt)
    }
    configDao.saveConfig(updatedCfg)

    var sessionsIngested = 0
    var sessionsTotal = 0
    sessionsResult.onSuccess { page ->
      sessionsTotal = page.total
      val entities = page.sessions.map { mapSessionDtoToEntity(it) }
      if (offset == 0) {
        sessionDao.clearByDemoFlag(false)
      }
      if (entities.isNotEmpty()) {
        sessionDao.insertAll(entities)
      }
      sessionsIngested = entities.size
    }

    var eventsIngested = 0
    var eventsTotal = 0
    eventsResult.onSuccess { page ->
      eventsTotal = page.total
      val entities = page.events.map { mapEventDtoToEntity(it) }
      if (offset == 0) {
        eventDao.clearByDemoFlag(false)
      }
      if (entities.isNotEmpty()) {
        eventDao.insertAll(entities)
      }
      eventsIngested = entities.size
    }

    val summaryMsg = "Sincronizado con daemon: $sessionsIngested/$sessionsTotal sesiones y $eventsIngested/$eventsTotal eventos."
    return Result.success(
      DaemonSyncSummary(
        message = summaryMsg,
        sessionsCount = sessionsIngested,
        sessionsTotal = sessionsTotal,
        eventsCount = eventsIngested,
        eventsTotal = eventsTotal,
        syncedAtMs = syncedAt
      )
    )
  }

  /**
   * Envía cambios de configuración al daemon vía PUT /api/config y persiste la respuesta real en Room.
   */
  suspend fun pushDaemonConfig(update: DaemonConfigUpdate): Result<DaemonConfigDto> {
    val cfg = configDao.getConfigOnce() ?: HoneygateConfigEntity(id = 1)
    val baseUrl = cfg.daemonBaseUrl.trim()
    val token = cfg.daemonAuthToken.trim()

    if (token.isEmpty()) {
      return Result.failure(Exception("Configurá el token para aplicar cambios en el daemon"))
    }
    if (baseUrl.isEmpty()) {
      return Result.failure(Exception("Configurá la URL del daemon"))
    }

    val result = daemonClient.updateConfig(baseUrl, token, update)
    result.onSuccess { dto ->
      val syncedAt = System.currentTimeMillis()
      val merged = mergeDaemonConfig(cfg, dto, syncedAt)
      configDao.saveConfig(merged)
    }
    return result
  }

  /**
   * Marca una sesión real como 'en_observacion' en el daemon (POST /api/sessions/{id}/observe).
   */
  suspend fun observeDaemonSession(
    session: MonitoredSessionEntity,
    reason: String
  ): Result<MonitoredSessionEntity> {
    if (session.isDemo) {
      val updatedDemo = session.copy(
        isInObservation = true,
        currentStatus = "en_observacion",
        observedReason = reason
      )
      sessionDao.insertOrUpdate(updatedDemo)
      return Result.success(updatedDemo)
    }

    val daemonId = session.daemonSessionId
      ?: return Result.failure(Exception("La sesión no tiene ID persistido en el daemon"))
    val cfg = configDao.getConfigOnce() ?: HoneygateConfigEntity(id = 1)
    val token = cfg.daemonAuthToken.trim()
    if (token.isEmpty()) {
      return Result.failure(Exception("Configurá el token"))
    }

    val result = daemonClient.observeSession(cfg.daemonBaseUrl, token, daemonId, reason)
    return result.map { dto ->
      val entity = mapSessionDtoToEntity(dto).copy(id = session.id)
      sessionDao.insertOrUpdate(entity)
      entity
    }
  }

  /**
   * Aísla o desbloquea una IP en el daemon (POST /api/isolate o /api/unblock) y actualiza caché si tuvo éxito.
   */
  suspend fun updateSessionIsolation(
    session: MonitoredSessionEntity,
    blocked: Boolean
  ): Result<String> {
    if (session.isDemo) {
      val updatedDemo = session.copy(
        isMacBlocked = blocked,
        currentStatus = if (blocked) "isolated" else "closed"
      )
      sessionDao.insertOrUpdate(updatedDemo)
      return Result.success("[DEMO] Sesión ${session.ipAddress} actualizada localmente")
    }

    val cfg = configDao.getConfigOnce() ?: HoneygateConfigEntity(id = 1)
    val token = cfg.daemonAuthToken.trim()
    if (token.isEmpty()) {
      return Result.failure(Exception("Configurá el token"))
    }
    if (session.ipAddress.isBlank()) {
      return Result.failure(Exception("Sesión sin IP de origen válida"))
    }

    val remoteResult = if (blocked) {
      daemonClient.remoteIsolate(
        cfg.daemonBaseUrl,
        token,
        session.ipAddress,
        "Aislamiento confirmado desde panel Android (device_id=${session.deviceId})"
      )
    } else {
      daemonClient.remoteUnblock(cfg.daemonBaseUrl, token, session.ipAddress)
    }

    remoteResult.onSuccess {
      sessionDao.insertOrUpdate(
        session.copy(
          isMacBlocked = blocked,
          currentStatus = if (blocked) "isolated" else "closed"
        )
      )
    }
    return remoteResult
  }

  suspend fun isolateIpFromEvent(ip: String, deviceId: String): Result<String> {
    if (ip.isBlank()) {
      return Result.failure(Exception("Evento sin IP de origen válida"))
    }
    val cfg = configDao.getConfigOnce() ?: HoneygateConfigEntity(id = 1)
    val token = cfg.daemonAuthToken.trim()
    if (token.isEmpty()) {
      return Result.failure(Exception("Configurá el token"))
    }
    return daemonClient.remoteIsolate(
      cfg.daemonBaseUrl,
      token,
      ip,
      "Aislamiento confirmado desde evento forense (device_id=$deviceId)"
    )
  }

  // ---------------------------------------------------------------------------
  // Flujos locales estrictamente acotados al Modo DEMO (apagado por defecto)
  // ---------------------------------------------------------------------------

  fun calculateCompositeDeviceId(
    mac: String,
    ssid: String = "Demo_WLAN",
    userAgent: String = "Demo_UA",
    canvasHash: String = "Demo_Canvas",
    ja3: String = "Demo_JA3",
    dhcpOpt55: String = "Demo_DHCP"
  ): String {
    val raw = "$mac|$ssid|$userAgent|$canvasHash|$ja3|$dhcpOpt55"
    val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray())
    return "demo_" + digest.take(8).joinToString("") { "%02x".format(it) }
  }

  suspend fun runDemoMode1Registration(email: String, ip: String, mac: String): Mode1AuthResult {
    val cfg = configDao.getConfigOnce()
    if (cfg?.demoModeEnabled != true) {
      return Mode1AuthResult(
        accepted = false,
        status = "disabled",
        message = "Modo DEMO desactivado. Conectá el daemon para datos reales.",
        deviceId = "",
        inObservation = false
      )
    }
    val nowStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
    val deviceId = calculateCompositeDeviceId(mac)
    val disposableDomains = listOf("tempmail.com", "guerrillamail.com", "10minutemail.com", "mailinator.com")
    val domain = email.substringAfter("@", "").lowercase()
    val inObservation = disposableDomains.any { domain.contains(it) }

    sessionDao.insertOrUpdate(
      MonitoredSessionEntity(
        mode = 1,
        deviceId = deviceId,
        macAddress = mac,
        ipAddress = ip,
        deviceType = "Demo Client",
        service = "portal-demo",
        connectedAt = System.currentTimeMillis(),
        lastActivity = System.currentTimeMillis(),
        visitorLabel = email,
        observedReason = if (inObservation) "[DEMO] Dominio temporal detectado" else "",
        isInObservation = inObservation,
        currentStatus = if (inObservation) "en_observacion" else "active",
        isDemo = true
      )
    )
    eventDao.insertEvent(
      ForensicEvent(
        eventType = if (inObservation) "Alerted" else "Normal",
        rawEventType = if (inObservation) "DEMO_SYBIL_OBSERVATION" else "DEMO_PORTAL_REGISTRATION",
        mode = 1,
        sourceIp = ip,
        macAddress = mac,
        deviceId = deviceId,
        description = "[DEMO] Registro de '$email' en portal demostrativo.",
        category = if (inObservation) "DEMO_SYBIL_OBSERVATION" else "DEMO_PORTAL_REGISTRATION",
        severity = if (inObservation) "warning" else "info",
        dateFormatted = nowStr,
        isDemo = true
      )
    )
    return Mode1AuthResult(
      accepted = true,
      status = if (inObservation) "en_observacion" else "active",
      message = if (inObservation) "[DEMO] Dispositivo marcado en observación." else "[DEMO] Registro local de demostración completado.",
      deviceId = deviceId,
      inObservation = inObservation
    )
  }

  suspend fun runDemoRedTeamCommand(canaryUser: String, command: String): Mode2ActionResult {
    val cfg = configDao.getConfigOnce()
    if (cfg?.demoModeEnabled != true) {
      return Mode2ActionResult(
        commandOutput = "Modo DEMO desactivado. Activá 'Modo DEMO' para pruebas locales sin daemon.",
        escalationLevel = "Modo real activo",
        isBlocked = false
      )
    }
    val nowStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
    val cmd = command.trim()
    val isExfil = cmd.startsWith("curl ") || cmd.startsWith("wget ") || cmd.startsWith("nc ")
    val isHoneytoken = cmd.contains("shadow") || cmd.contains("AWS_SECRET")
    val out = when {
      isExfil -> "[DEMO] Simulación de sinkhole local para '$cmd'"
      isHoneytoken -> "[DEMO] Simulación de alerta honeytoken para '$canaryUser'"
      else -> "[DEMO] Comando '$cmd' registrado en entorno de demostración"
    }
    eventDao.insertEvent(
      ForensicEvent(
        eventType = if (isExfil || isHoneytoken) "Blocked" else "Alerted",
        rawEventType = if (isHoneytoken) "DEMO_HONEYTOKEN" else "DEMO_REDTEAM_CMD",
        mode = 2,
        description = "[DEMO] Red Team ($canaryUser): $cmd",
        category = "DEMO_REDTEAM_CMD",
        severity = if (isExfil || isHoneytoken) "critical" else "warning",
        dateFormatted = nowStr,
        isDemo = true
      )
    )
    return Mode2ActionResult(
      commandOutput = out,
      escalationLevel = if (isHoneytoken) "[DEMO] Honeytoken" else "[DEMO] Actividad simulada",
      isBlocked = isExfil
    )
  }

  companion object {
    fun mergeDaemonConfig(
      current: HoneygateConfigEntity,
      dto: DaemonConfigDto,
      syncedAtMs: Long
    ): HoneygateConfigEntity {
      return current.copy(
        gateMode = dto.mode,
        retentionDays = dto.retentionDays,
        maxOutboundPerMinute = dto.maxOutboundPerMinute,
        portalEnabled = dto.portalEnabled,
        honeypotEnabled = dto.honeypotEnabled,
        allowedOutboundWhitelistCsv = dto.egressWhitelist.joinToString(", "),
        sybilMaxEmailsPerDevice = dto.sybilMaxEmailsPerDevice,
        sybilWindowSeconds = dto.sybilWindowSeconds,
        configUpdatedAtSec = dto.updatedAt,
        lastSyncedAtMs = syncedAtMs
      )
    }

    fun mapSessionDtoToEntity(dto: DaemonSessionDto): MonitoredSessionEntity {
      return MonitoredSessionEntity(
        daemonSessionId = dto.id,
        mode = dto.mode,
        deviceId = dto.deviceId,
        macAddress = dto.mac,
        ipAddress = dto.ip,
        clientPort = dto.clientPort,
        deviceType = dto.deviceType,
        browserFingerprint = dto.browserFingerprint,
        networkFingerprint = dto.networkFingerprint,
        dhcpFingerprint = dto.dhcpFingerprint,
        destIp = dto.destIp,
        destPort = dto.destPort,
        service = dto.service,
        honeytokenTouched = dto.honeytokenTouched,
        connectedAt = (dto.startedAt * 1000.0).toLong(),
        endedAt = dto.endedAt?.let { (it * 1000.0).toLong() },
        lastActivity = ((dto.endedAt ?: dto.startedAt) * 1000.0).toLong(),
        durationSeconds = dto.durationSec.toLong(),
        bytesIn = dto.bytesIn,
        bytesOut = dto.bytesOut,
        visitorLabel = dto.visitorLabel ?: "",
        observedReason = dto.observedReason ?: "",
        isMacBlocked = dto.status == "isolated",
        isInObservation = dto.status == "en_observacion",
        currentStatus = dto.status,
        isDemo = false
      )
    }

    fun mapEventDtoToEntity(dto: DaemonEventDto): ForensicEvent {
      val sevLower = dto.severity.lowercase()
      val typeUpper = dto.eventType.uppercase()
      val uiBucket = when {
        sevLower == "critical" || typeUpper.contains("ISOLAT") || typeUpper.contains("DROPPED") || typeUpper.contains("CONTAINMENT") -> "Blocked"
        sevLower == "warning" || typeUpper.contains("OBSERVED") || typeUpper.contains("FAILED") -> "Alerted"
        else -> "Normal"
      }
      return ForensicEvent(
        daemonEventId = dto.id,
        sessionId = dto.sessionId,
        timestamp = (dto.timestamp * 1000.0).toLong(),
        eventType = uiBucket,
        rawEventType = dto.eventType,
        mode = dto.mode,
        sourceIp = dto.ip ?: "",
        macAddress = dto.metadataMac ?: "",
        description = dto.description,
        deviceId = dto.deviceId ?: "",
        category = dto.eventType,
        severity = dto.severity,
        destinationTarget = dto.metadataTarget ?: "",
        honeytokenTouched = dto.metadataHoneytoken,
        mitreTechnique = dto.mitreTechnique ?: "",
        isCorrelated = dto.sessionId != null,
        dateFormatted = dto.createdAt,
        isDemo = false
      )
    }
  }
}

data class Mode1AuthResult(
  val accepted: Boolean,
  val status: String,
  val message: String,
  val deviceId: String,
  val inObservation: Boolean
)

data class Mode2ActionResult(
  val commandOutput: String,
  val escalationLevel: String,
  val isBlocked: Boolean
)

data class OtpChallenge(
  val email: String,
  val code: String,
  val deviceId: String,
  val timestamp: Long
)
