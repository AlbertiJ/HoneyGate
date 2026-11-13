package com.example.data.repository

import com.example.data.local.dao.ForensicEventDao
import com.example.data.local.dao.HoneygateConfigDao
import com.example.data.local.dao.MonitoredSessionDao
import com.example.data.local.entity.ForensicEvent
import com.example.data.local.entity.HoneygateConfigEntity
import com.example.data.local.entity.MonitoredSessionEntity
import com.example.data.remote.DaemonAlert
import com.example.data.remote.DaemonSession
import com.example.data.remote.DaemonStatus
import com.example.data.remote.HoneyGateDaemonClient
import kotlinx.coroutines.flow.Flow
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class HoneyGateRepository(
  private val eventDao: ForensicEventDao,
  private val sessionDao: MonitoredSessionDao,
  private val configDao: HoneygateConfigDao
) {
  private val daemonClient = HoneyGateDaemonClient()

  val allEvents: Flow<List<ForensicEvent>> = eventDao.getAllEvents()
  val allSessions: Flow<List<MonitoredSessionEntity>> = sessionDao.getAllSessions()
  val honeygateConfig: Flow<HoneygateConfigEntity?> = configDao.getConfig()

  fun getEventsByType(type: String): Flow<List<ForensicEvent>> {
    return if (type == "All") {
      eventDao.getAllEvents()
    } else {
      eventDao.getEventsByType(type)
    }
  }

  suspend fun insertEvent(event: ForensicEvent) = eventDao.insertEvent(event)

  suspend fun deleteEvent(id: Long) = eventDao.deleteEventById(id)

  suspend fun clearAllEvents() = eventDao.clearAll()

  suspend fun saveHoneygateConfig(config: HoneygateConfigEntity) = configDao.saveConfig(config)

  suspend fun getConfigOnce(): HoneygateConfigEntity? = configDao.getConfigOnce()

  /**
   * Invariante 1: Generación del Fingerprint Compuesto (device_id inmutable).
   * Combina MAC-por-SSID + Browser Fingerprint + Network JA3 + DHCP Fingerprint.
   */
  fun calculateCompositeDeviceId(
    mac: String,
    ssid: String = "Corp_Secure_WLAN",
    userAgent: String = "Mozilla/5.0 (Linux; Android 14) Mobile",
    canvasHash: String = "Canvas_A9F1",
    ja3: String = "JA3_771_TLS",
    dhcpOpt55: String = "DHCP_55_1_15_3_6"
  ): String {
    val raw = "$mac|$ssid|$userAgent|$canvasHash|$ja3|$dhcpOpt55"
    val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray())
    return "dev_" + digest.take(8).joinToString("") { "%02x".format(it) }
  }

  /**
   * Bloqueo confirmado por administrador (Invariante 5).
   * Si el Daemon Linux está configurado y activo, dispara inmediatamente
   * el aislamiento a nivel de kernel mediante shutdown(fd, SHUT_RDWR).
   */
  suspend fun updateMacBlockStatus(mac: String, deviceId: String, blocked: Boolean) {
    sessionDao.setMacBlockedStatus(mac, blocked)
    if (deviceId.isNotBlank()) {
      sessionDao.setDeviceBlockedStatus(deviceId, blocked)
    }

    val session = sessionDao.getSessionByMac(mac) ?: if (deviceId.isNotBlank()) sessionDao.getSessionByDeviceId(deviceId) else null
    val targetIp = session?.ipAddress ?: "0.0.0.0"

    // Disparo de contención perimetral remota en el daemon de Linux si está activo
    val config = configDao.getConfigOnce()
    var daemonMsg = ""
    if (config != null && config.daemonSyncEnabled && config.daemonBaseUrl.isNotBlank() && targetIp.isNotBlank() && targetIp != "0.0.0.0") {
      val token = config.daemonAuthToken.trim()
      if (token.isEmpty()) {
        daemonMsg = " [Daemon Linux: Configurá el token]"
      } else {
        val remoteResult = if (blocked) {
          daemonClient.remoteIsolate(config.daemonBaseUrl, token, targetIp, "Bloqueo confirmado por administrador en app HoneyGate para MAC $mac / $deviceId")
        } else {
          daemonClient.remoteUnblock(config.daemonBaseUrl, token, targetIp)
        }
        daemonMsg = remoteResult.fold(
          onSuccess = { " [Kernel Linux: $it]" },
          onFailure = { " [Daemon Linux no alcanzado: ${it.localizedMessage}]" }
        )
      }
    }

    val now = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
    eventDao.insertEvent(
      ForensicEvent(
        eventType = if (blocked) "Blocked" else "Alerted",
        sourceIp = targetIp,
        macAddress = mac,
        deviceId = deviceId,
        description = "Acción de Administrador confirmada: ${if (blocked) "BLOQUEO EN CASCADA" else "DESBLOQUEO"} aplicado a la MAC $mac y device_id $deviceId.$daemonMsg",
        category = "ADMIN_CONTAINMENT",
        severity = if (blocked) "CRITICAL" else "MEDIUM",
        mitreTechnique = "T1562 - Impair Defenses (Mitigación Defensiva)",
        dateFormatted = now
      )
    )
  }

  /**
   * Consulta el estado en vivo del Daemon de HoneyGate en Linux (GET /api/status).
   */
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
   * Sincroniza la telemetría en vivo del Daemon Linux con la base de datos Room:
   * - Ingesta sesiones activas de kernel (GET /api/connections).
   * - Ingesta alertas forenses de inotify y honeypot (GET /api/alerts).
   */
  suspend fun syncWithDaemon(baseUrl: String, token: String): Result<String> {
    if (token.isBlank()) {
      return Result.failure(Exception("Configurá el token"))
    }
    val sessionsResult = daemonClient.getActiveSessions(baseUrl, token)
    val alertsResult = daemonClient.getAlerts(baseUrl, token)

    var sessionsIngested = 0
    var alertsIngested = 0

    sessionsResult.onSuccess { sessions ->
      sessions.forEach { s ->
        val devId = calculateCompositeDeviceId(s.mac)
        val existing = sessionDao.getSessionByDeviceId(devId) ?: sessionDao.getSessionByMac(s.mac)
        val entity = (existing ?: MonitoredSessionEntity(deviceId = devId, macAddress = s.mac, ipAddress = s.ip)).copy(
          deviceId = devId,
          macAddress = s.mac,
          ipAddress = s.ip,
          durationSeconds = s.durationSec,
          outboundRequestsCount = s.outboundRateMin,
          lastActivity = System.currentTimeMillis()
        )
        sessionDao.insertOrUpdate(entity)
        sessionsIngested++
      }
    }

    alertsResult.onSuccess { alerts ->
      val now = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
      alerts.forEach { a ->
        eventDao.insertEvent(
          ForensicEvent(
            eventType = when (a.severity.lowercase()) {
              "blocked", "critical" -> "Blocked"
              "alerted", "high", "medium" -> "Alerted"
              else -> "Normal"
            },
            sourceIp = "127.0.0.1",
            macAddress = "00:00:00:00:00:00",
            deviceId = "dev_daemon_sync",
            description = "[Daemon Linux] ${a.title}: ${a.message}",
            category = "DAEMON_SYNC_ALERT",
            severity = a.severity.uppercase(),
            mitreTechnique = "T1046 - Network Service Discovery",
            dateFormatted = if (a.date.isNotBlank()) a.date else now,
            isCorrelated = true
          )
        )
        alertsIngested++
      }
    }

    return if (sessionsResult.isSuccess || alertsResult.isSuccess) {
      Result.success("Telemetría sincronizada: $sessionsIngested sesiones activas y $alertsIngested alertas forenses.")
    } else {
      Result.failure(sessionsResult.exceptionOrNull() ?: alertsResult.exceptionOrNull() ?: Exception("Fallo en sincronización con Daemon"))
    }
  }

  /**
   * MODO 1: Portal cautivo con trazabilidad (monitoreo básico).
   * - Registro SOLO con email (sin clave obligatoria).
   * - Anti-Sybil: limitar/marcar múltiples registros desde un mismo device_id.
   * - Reglas de velocidad: mails desechables, rotación de MAC con mismo navegador.
   * - Marca 'en observación' (reduce lease DHCP a 300s, loguea, no bloquea de una).
   */
  suspend fun processMode1Registration(
    email: String,
    ip: String,
    mac: String,
    ssid: String = "Corp_Secure_WLAN",
    browserFingerprint: String = "Canvas_A9F1",
    ja3: String = "JA3_771"
  ): Mode1AuthResult {
    val now = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
    val deviceId = calculateCompositeDeviceId(mac, ssid, canvasHash = browserFingerprint, ja3 = ja3)
    val existingSession = sessionDao.getSessionByDeviceId(deviceId) ?: sessionDao.getSessionByMac(mac)

    // 1. Detección de dominio de email temporal / desechable
    val disposableDomains = listOf("tempmail.com", "guerrillamail.com", "10minutemail.com", "mailinator.com", "throwaway.email")
    val domain = email.substringAfter("@", "").lowercase()
    val isDisposable = disposableDomains.any { domain.contains(it) }

    if (isDisposable) {
      val session = (existingSession ?: MonitoredSessionEntity(deviceId = deviceId, macAddress = mac, ipAddress = ip)).copy(
        deviceId = deviceId,
        ipAddress = ip,
        lastActivity = System.currentTimeMillis(),
        isInObservation = true,
        dhcpLeaseSeconds = 300,
        currentStatus = "Alerted",
        detectedAnomaliesCsv = "DISPOSABLE_EMAIL_DOMAIN"
      )
      sessionDao.insertOrUpdate(session)

      eventDao.insertEvent(
        ForensicEvent(
          eventType = "Alerted",
          sourceIp = ip,
          macAddress = mac,
          deviceId = deviceId,
          description = "Anti-Sybil: Intento de registro con dominio desechable '$domain'. Dispositivo $deviceId marcado en observación. Lease DHCP reducido a 300s.",
          category = "ANTI_SYBIL_DISPOSABLE",
          severity = "HIGH",
          mitreTechnique = "T1586.002 - Compromise Accounts: Email Accounts",
          dateFormatted = now
        )
      )

      return Mode1AuthResult(
        accepted = true,
        status = "Alerted",
        message = "Registro completado en modo observación (dominio no corporativo). Acceso regulado.",
        deviceId = deviceId,
        inObservation = true
      )
    }

    // 2. Anti-Sybil: Múltiples emails desde el mismo device_id
    val previousEmails = existingSession?.emailsUsedCsv?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
    val isMultiEmail = previousEmails.isNotEmpty() && !previousEmails.contains(email)

    if (isMultiEmail && previousEmails.size >= 2) {
      val updatedEmails = (previousEmails + email).distinct().joinToString(", ")
      val session = (existingSession ?: MonitoredSessionEntity(deviceId = deviceId, macAddress = mac, ipAddress = ip)).copy(
        deviceId = deviceId,
        ipAddress = ip,
        lastActivity = System.currentTimeMillis(),
        emailsUsedCsv = updatedEmails,
        isInObservation = true,
        dhcpLeaseSeconds = 300,
        currentStatus = "Alerted",
        detectedAnomaliesCsv = "MULTI_ACCOUNT_VELOCITY"
      )
      sessionDao.insertOrUpdate(session)

      eventDao.insertEvent(
        ForensicEvent(
          eventType = "Alerted",
          sourceIp = ip,
          macAddress = mac,
          deviceId = deviceId,
          description = "Anti-Sybil: Múltiples registros detectados (${previousEmails.size + 1}) bajo el mismo device_id $deviceId. Dispositivo en observación con lease DHCP de 5 min.",
          category = "ANTI_SYBIL_MULTI_USER",
          severity = "HIGH",
          mitreTechnique = "T1078 - Valid Accounts",
          dateFormatted = now,
          isCorrelated = true
        )
      )

      return Mode1AuthResult(
        accepted = true,
        status = "Alerted",
        message = "Identidad registrada. Tráfico asignado a perfil de auditoría con telemetría de sesión.",
        deviceId = deviceId,
        inObservation = true
      )
    }

    // 3. Registro Nominal Normal (Consentimiento Ley 25.326 aceptado)
    val updatedEmails = (previousEmails + email).distinct().joinToString(", ")
    val session = (existingSession ?: MonitoredSessionEntity(deviceId = deviceId, macAddress = mac, ipAddress = ip)).copy(
      deviceId = deviceId,
      macAddress = mac,
      ipAddress = ip,
      lastActivity = System.currentTimeMillis(),
      emailsUsedCsv = updatedEmails,
      currentStatus = "Normal",
      consentAccepted = true
    )
    sessionDao.insertOrUpdate(session)

    eventDao.insertEvent(
      ForensicEvent(
        eventType = "Normal",
        sourceIp = ip,
        macAddress = mac,
        deviceId = deviceId,
        description = "Registro nominal verificado para '$email'. Metadatos registrados bajo Ley 25.326. Lease DHCP asignado: 3600s.",
        category = "PORTAL_REGISTRATION",
        severity = "LOW",
        mitreTechnique = "T1078 - Valid Accounts",
        dateFormatted = now
      )
    )

    return Mode1AuthResult(
      accepted = true,
      status = "Normal",
      message = "Registro exitoso. Navegación habilitada con trazabilidad nominal.",
      deviceId = deviceId,
      inObservation = false
    )
  }

  /**
   * MODO 2: Honeypot (auditoría para un cliente / Red Team).
   * - Assume-breach con 3 canary users de áreas (sin claves).
   * - Invariante 2: Contención de salida (whitelist / sinkhole).
   * - Invariante 3: Detección y alerta de Honeytokens.
   * - Captura de comandos y técnicas MITRE.
   */
  suspend fun processMode2RedTeamAction(
    canaryUser: String,
    command: String,
    ip: String = "10.0.8.44",
    mac: String = "aa:bb:cc:dd:ee:01"
  ): Mode2ActionResult {
    val now = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
    val deviceId = calculateCompositeDeviceId(mac, "RedTeam_Honeypot_VLAN")
    val cmd = command.trim()

    // 1. Detección de Honeytokens tocados (Invariante 3)
    val touchedHoneytoken = when {
      cmd.contains("/etc/shadow") || cmd.contains("shadow") -> "Honeytoken: Hash de root ficticio (\$6\$fakeSalt\$HoneyToken...)"
      cmd.contains("AWS_SECRET") || cmd.contains(".env") -> "Honeytoken: AWS_SECRET_CANARY_X99A"
      cmd.contains("SWIFT") || cmd.contains("transfer") -> "Honeytoken: DB_SWIFT_ROUTING_KEY_HONEY"
      else -> null
    }

    // 2. Invariante 2: Contención de salida (Intento de exfiltración o conexión externa)
    val isOutboundAttempt = cmd.contains("curl ") || cmd.contains("wget ") || cmd.contains("nc ") || cmd.contains("ssh ")
    val isWhitelisted = cmd.contains("dns.google.com") || cmd.contains("corp.internal.net")

    if (isOutboundAttempt && !isWhitelisted) {
      eventDao.insertEvent(
        ForensicEvent(
          eventType = "Blocked",
          sourceIp = ip,
          macAddress = mac,
          deviceId = deviceId,
          description = "Contención de Salida (Invariante 2): Tráfico saliente bloqueado hacia destino no listado. Comando: '$cmd' redirigido a Sinkhole local.",
          category = "EGRESS_CONTAINMENT_SINKHOLE",
          severity = "CRITICAL",
          destinationTarget = "SINKHOLE_127.0.0.1",
          mitreTechnique = "T1048 - Exfiltration Over Alternative Protocol",
          dateFormatted = now,
          isCorrelated = true
        )
      )

      return Mode2ActionResult(
        commandOutput = "[SINKHOLE TRIGGERED] Conexión saliente contenida por política de HoneyGate. Redirigida a 127.0.0.1:0 (Drop pasivo).",
        escalationLevel = "Nivel 2: Intento de Exfiltración Contenido",
        isBlocked = true
      )
    }

    if (touchedHoneytoken != null) {
      eventDao.insertEvent(
        ForensicEvent(
          eventType = "Blocked",
          sourceIp = ip,
          macAddress = mac,
          deviceId = deviceId,
          description = "¡ALERTA CRÍTICA HONEYTOKEN! El Red Team tocó un dato señuelo controlado: $touchedHoneytoken mediante '$cmd' con el usuario canary $canaryUser.",
          category = "HONEYTOKEN_TRIGGERED",
          severity = "CRITICAL",
          honeytokenTouched = touchedHoneytoken,
          mitreTechnique = "T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow",
          dateFormatted = now,
          isCorrelated = true
        )
      )

      return Mode2ActionResult(
        commandOutput = "root:\$6\$fakeSalt\$HoneyTokenHashK8J9...:19420:0:99999:7::: (Honeytoken Activo)",
        escalationLevel = "Nivel 3: Compromiso de Honeytoken (Alerta Inmediata al Blue Team)",
        isBlocked = false
      )
    }

    // Mapeo general de comandos
    val (output, level, technique) = when {
      cmd.contains("sudo -l") -> Triple(
        "(ALL) NOPASSWD: /usr/bin/service_emulator",
        "Nivel 2: Enumeración de Sudoers",
        "T1548.003 - Abuse Elevation Control Mechanism: Sudo"
      )
      cmd.contains("id") || cmd.contains("whoami") -> Triple(
        "uid=1001($canaryUser) gid=1001(canary_sector) groups=1001(canary)",
        "Nivel 1: Acceso Inicial Canary",
        "T1033 - System Owner/User Discovery"
      )
      cmd.contains("netstat") || cmd.contains("ss ") -> Triple(
        "Active Internet connections (servers and established)\ntcp 0 0 0.0.0.0:2222 0.0.0.0:* LISTEN (Emulated SSH)\ntcp 0 0 0.0.0.0:3306 0.0.0.0:* LISTEN (Emulated MySQL)\ntcp 0 0 0.0.0.0:8080 0.0.0.0:* LISTEN (Emulated Apache)",
        "Nivel 1: Reconocimiento de Puertos",
        "T1046 - Network Service Discovery"
      )
      else -> Triple(
        "Comando '$cmd' procesado por el entorno emulado de HoneyGate.",
        "Nivel 1: Actividad General",
        "T1059 - Command and Scripting Interpreter"
      )
    }

    eventDao.insertEvent(
      ForensicEvent(
        eventType = "Alerted",
        sourceIp = ip,
        macAddress = mac,
        deviceId = deviceId,
        description = "Red Team [$canaryUser]: Ejecución de comando '$cmd'. TTP detectada y correlacionada.",
        category = "REDTEAM_COMMAND_EXEC",
        severity = "HIGH",
        mitreTechnique = technique,
        dateFormatted = now
      )
    )

    return Mode2ActionResult(
      commandOutput = output,
      escalationLevel = level,
      isBlocked = false
    )
  }

  /**
   * Pre-carga de datos iniciales en la base de datos Room.
   */
  suspend fun preseedInitialDataIfEmpty() {
    val initialConfig = HoneygateConfigEntity(
      id = 1,
      gateMode = 1,
      companyName = "AeroSec Global Defense Corp",
      primaryColorHex = "#10B981",
      accentColorHex = "#06B6D4",
      strictEgressContainment = true,
      honeytokensActive = true,
      legalConsentBannerEnabled = true
    )
    if (configDao.getConfigOnce() == null) {
      configDao.saveConfig(initialConfig)
    }

    val sampleEvents = listOf(
      ForensicEvent(
        timestamp = System.currentTimeMillis() - 150000,
        eventType = "Blocked",
        sourceIp = "198.51.100.42",
        macAddress = "08:00:27:fa:31:0a",
        deviceId = "dev_a1b2c3d4",
        description = "Contención Perimetral: Pivoteo saliente mitigado tras exceder umbral de 10 tramas/min. Syscall shutdown(SHUT_RDWR) ejecutada.",
        category = "RATE_LIMIT_PIVOTING",
        severity = "CRITICAL",
        mitreTechnique = "T1046 - Network Service Discovery",
        dateFormatted = "18:42:10",
        isCorrelated = true
      ),
      ForensicEvent(
        timestamp = System.currentTimeMillis() - 110000,
        eventType = "Alerted",
        sourceIp = "192.168.1.105",
        macAddress = "52:54:00:12:34:56",
        deviceId = "dev_e5f6g7h8",
        description = "Invariante 3 (Honeytoken Activo): El usuario canary 'cfo_canary@honeygate.corp' tocó el archivo señuelo /etc/shadow. Payload registrado.",
        category = "HONEYTOKEN_TRIGGERED",
        severity = "HIGH",
        honeytokenTouched = "/etc/shadow (Honeytoken Root Hash)",
        mitreTechnique = "T1003.008 - OS Credential Dumping",
        dateFormatted = "18:45:30",
        isCorrelated = true
      ),
      ForensicEvent(
        timestamp = System.currentTimeMillis() - 75000,
        eventType = "Alerted",
        sourceIp = "172.16.4.88",
        macAddress = "00:1a:2b:3c:4d:5e",
        deviceId = "dev_8899aabb",
        description = "Anti-Sybil: Múltiples registros (3 identidades) desde el mismo device_id dev_8899aabb. Dispositivo puesto en observación (lease DHCP: 300s).",
        category = "ANTI_SYBIL_MULTI_USER",
        severity = "MEDIUM",
        mitreTechnique = "T1078 - Valid Accounts",
        dateFormatted = "18:49:12"
      ),
      ForensicEvent(
        timestamp = System.currentTimeMillis() - 40000,
        eventType = "Normal",
        sourceIp = "10.0.2.15",
        macAddress = "00:50:56:c0:00:08",
        deviceId = "dev_12345678",
        description = "Registro nominal bajo Modo 1 para 'jmartinez@aerosec.corp'. Consentimiento de metadatos Ley 25.326 verificado. Salida autorizada.",
        category = "PORTAL_REGISTRATION",
        severity = "LOW",
        mitreTechnique = "T1078 - Valid Accounts",
        dateFormatted = "18:52:04"
      )
    )

    eventDao.insertAll(sampleEvents)

    val sampleSessions = listOf(
      MonitoredSessionEntity(
        deviceId = "dev_a1b2c3d4",
        macAddress = "08:00:27:fa:31:0a",
        ipAddress = "198.51.100.42",
        durationSeconds = 140,
        emailsUsedCsv = "scan_attacker@mail.com",
        isMacBlocked = true,
        outboundRequestsCount = 14,
        detectedAnomaliesCsv = "RATE_LIMIT_EXCEEDED",
        currentStatus = "Blocked"
      ),
      MonitoredSessionEntity(
        deviceId = "dev_e5f6g7h8",
        macAddress = "52:54:00:12:34:56",
        ipAddress = "192.168.1.105",
        durationSeconds = 520,
        emailsUsedCsv = "cfo_canary@honeygate.corp, redteam_probe@honeygate.corp",
        isInObservation = true,
        dhcpLeaseSeconds = 300,
        outboundRequestsCount = 8,
        visitedUrlsCsv = "honeygate.portal/auth, intranet.corp/secrets",
        detectedAnomaliesCsv = "HONEYTOKEN_TOUCHED, MULTI_ACCOUNT",
        currentStatus = "Alerted"
      ),
      MonitoredSessionEntity(
        deviceId = "dev_12345678",
        macAddress = "00:50:56:c0:00:08",
        ipAddress = "10.0.2.15",
        durationSeconds = 890,
        emailsUsedCsv = "jmartinez@aerosec.corp",
        currentStatus = "Normal",
        consentAccepted = true
      )
    )

    sampleSessions.forEach { sessionDao.insertOrUpdate(it) }
  }

  /**
   * Detección y correlación de Inyección SQL (SQLi) en el portal de autenticación.
   * Si un atacante inyecta SQL para validar claves sin usuario registrado:
   * 1. Se verifica la MAC y sus IPs asignadas en otras cuentas.
   * 2. Se mantiene la correlación activa y se permite navegación monitorizada (sin cortar bruscamente).
   * 3. Se genera un evento de alerta crítica y aviso al panel de administración para bloqueo en cascada.
   */
  suspend fun processSqlInjectionProbe(
    payload: String,
    ip: String = "192.168.1.189",
    mac: String = "52:54:00:88:99:aa"
  ): SqlInjectionResult {
    val now = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
    val deviceId = calculateCompositeDeviceId(mac)
    val existingSession = sessionDao.getSessionByDeviceId(deviceId) ?: sessionDao.getSessionByMac(mac)

    val session = (existingSession ?: MonitoredSessionEntity(deviceId = deviceId, macAddress = mac, ipAddress = ip)).copy(
      deviceId = deviceId,
      macAddress = mac,
      ipAddress = ip,
      lastActivity = System.currentTimeMillis(),
      isInObservation = true,
      dhcpLeaseSeconds = 300,
      currentStatus = "Alerted",
      detectedAnomaliesCsv = if (existingSession?.detectedAnomaliesCsv.isNullOrBlank()) "SQL_INJECTION_ATTEMPT" else "${existingSession?.detectedAnomaliesCsv}, SQL_INJECTION_ATTEMPT"
    )
    sessionDao.insertOrUpdate(session)

    val alertMsg = "Inyección SQL detectada: Payload '$payload' en validación de credenciales. Correlación activa: MAC $mac (IP $ip, device_id $deviceId). Navegación monitorizada y aviso al administrador disponible para bloqueo en cascada."

    eventDao.insertEvent(
      ForensicEvent(
        eventType = "Alerted",
        sourceIp = ip,
        macAddress = mac,
        deviceId = deviceId,
        description = alertMsg,
        category = "SQL_INJECTION_DETECTED",
        severity = "CRITICAL",
        mitreTechnique = "T1190 - Exploit Public-Facing Application",
        dateFormatted = now,
        isCorrelated = true
      )
    )

    return SqlInjectionResult(
      detected = true,
      payload = payload,
      correlatedIp = ip,
      correlatedMac = mac,
      deviceId = deviceId,
      alertMessage = alertMsg
    )
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

data class SqlInjectionResult(
  val detected: Boolean,
  val payload: String,
  val correlatedIp: String,
  val correlatedMac: String,
  val deviceId: String,
  val alertMessage: String
)

data class OtpChallenge(
  val email: String,
  val code: String,
  val deviceId: String,
  val timestamp: Long
)
