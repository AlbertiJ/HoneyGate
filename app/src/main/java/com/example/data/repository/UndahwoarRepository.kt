package com.example.data.repository

import com.example.data.local.dao.ForensicEventDao
import com.example.data.local.dao.HoneygateConfigDao
import com.example.data.local.dao.MonitoredSessionDao
import com.example.data.local.entity.ForensicEventEntity
import com.example.data.local.entity.HoneygateConfigEntity
import com.example.data.local.entity.MonitoredSessionEntity
import kotlinx.coroutines.flow.Flow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class UndahwoarRepository(
  private val eventDao: ForensicEventDao,
  private val sessionDao: MonitoredSessionDao,
  private val configDao: HoneygateConfigDao
) {
  val allEvents: Flow<List<ForensicEventEntity>> = eventDao.getAllEvents()
  val allSessions: Flow<List<MonitoredSessionEntity>> = sessionDao.getAllSessions()
  val honeygateConfig: Flow<HoneygateConfigEntity?> = configDao.getConfig()

  fun getEventsByStatus(status: String): Flow<List<ForensicEventEntity>> {
    return if (status == "All") {
      eventDao.getAllEvents()
    } else {
      eventDao.getEventsByStatus(status)
    }
  }

  suspend fun insertEvent(event: ForensicEventEntity) = eventDao.insertEvent(event)

  suspend fun deleteEvent(id: Long) = eventDao.deleteEventById(id)

  suspend fun clearAllEvents() = eventDao.clearAll()

  suspend fun saveHoneygateConfig(config: HoneygateConfigEntity) = configDao.saveConfig(config)

  suspend fun updateMacBlockStatus(mac: String, blocked: Boolean) {
    sessionDao.setMacBlockedStatus(mac, blocked)
    val now = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
    eventDao.insertEvent(
      ForensicEventEntity(
        dateFormatted = now,
        status = if (blocked) "Blocked" else "Alerted",
        severity = if (blocked) "CRITICAL" else "MEDIUM",
        category = "ADMIN_CONTAINMENT",
        title = if (blocked) "Contención Perimetral Activada" else "Contención Levantada",
        description = "La dirección MAC $mac y todas sus identidades asociadas han sido ${if (blocked) "BLOQUEADAS" else "DESBLOQUEADAS"} por el Administrador.",
        sourceIp = "0.0.0.0",
        macAddress = mac,
        mitreTechnique = "T1562 - Impair Defenses (Mitigación Defensiva)"
      )
    )
  }

  /**
   * Procesa un intento de registro o login en la Puerta de Miel (Honeygate Opción 1).
   * Detecta:
   *  1. Inyección SQL (SQLi).
   *  2. Múltiples cuentas registradas desde la misma MAC/IP -> 'Alerted', permite navegar pero audita.
   *  3. Intentos reiterados fallidos -> deshabilita email pero mantiene monitoreo de MAC.
   */
  suspend fun processHoneygateAuthAttempt(
    ip: String,
    mac: String,
    email: String,
    passwordAttempt: String,
    otpCode: String?
  ): AuthResult {
    val now = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
    val existingSession = sessionDao.getSessionByMac(mac)

    // 1. Detección de Inyección SQL (SQLi)
    val sqlPatterns = listOf(
      "' OR '", "' OR '1'='1", "UNION SELECT", "admin' --", "'--",
      "OR 1=1", "DROP TABLE", "SLEEP(", "WAITFOR DELAY", "1' ORDER BY"
    )
    val isSqlInjection = sqlPatterns.any {
      email.uppercase().contains(it.uppercase()) || passwordAttempt.uppercase().contains(it.uppercase())
    }

    if (isSqlInjection) {
      // Verificar si la MAC tiene IP asignada en otra cuenta de usuario para correlación
      val previousEmails = existingSession?.emailsUsedCsv ?: ""
      val isCorrelated = previousEmails.isNotBlank() && !previousEmails.contains(email)

      eventDao.insertEvent(
        ForensicEventEntity(
          dateFormatted = now,
          status = "Alerted",
          severity = "CRITICAL",
          category = "SQL_INJECTION",
          title = "Intento de Inyección SQL Detectado",
          description = "Payload malicioso detectado en Honeygate: '$passwordAttempt'. Correlación MAC: $mac posee historial previo con usuario(s): [$previousEmails]. Alerta emitida al Administrador.",
          sourceIp = ip,
          macAddress = mac,
          associatedEmail = email,
          mitreTechnique = "T1190 - Exploit Public-Facing Application (SQLi)",
          rawPayload = passwordAttempt,
          isCorrelated = isCorrelated
        )
      )

      val updatedEmails = if (previousEmails.contains(email)) previousEmails else "$previousEmails, $email".trim(',', ' ')
      sessionDao.insertOrUpdate(
        (existingSession ?: MonitoredSessionEntity(macAddress = mac, ipAddress = ip)).copy(
          ipAddress = ip,
          lastActivity = System.currentTimeMillis(),
          emailsUsedCsv = updatedEmails,
          detectedAnomaliesCsv = "SQL_INJECTION_DETECTED",
          currentStatus = "Alerted"
        )
      )

      return AuthResult(
        success = false,
        status = "Alerted",
        message = "Alerta de Seguridad: Se ha detectado sintaxis sospechosa. Sesión marcada para auditoría.",
        shouldAllowNavigation = true
      )
    }

    // 2. Detección de Múltiples Usuarios desde la misma MAC o IP
    val currentEmailsList = existingSession?.emailsUsedCsv?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
    val isMultiUser = currentEmailsList.isNotEmpty() && !currentEmailsList.contains(email)

    if (isMultiUser) {
      val allEmails = (currentEmailsList + email).distinct().joinToString(", ")
      eventDao.insertEvent(
        ForensicEventEntity(
          dateFormatted = now,
          status = "Alerted",
          severity = "HIGH",
          category = "MULTI_USER_MAC",
          title = "Anomalía de Registro: Múltiples Cuentas en Misma MAC",
          description = "La dirección MAC $mac ha registrado/utilizado ${currentEmailsList.size + 1} cuentas distintas: [$allEmails]. Se autoriza navegación en modo engañoso con auditoría continua de destinos.",
          sourceIp = ip,
          macAddress = mac,
          associatedEmail = email,
          mitreTechnique = "T1078 - Valid Accounts (Account Aggregation)",
          isCorrelated = true
        )
      )

      sessionDao.insertOrUpdate(
        (existingSession ?: MonitoredSessionEntity(macAddress = mac, ipAddress = ip)).copy(
          ipAddress = ip,
          lastActivity = System.currentTimeMillis(),
          emailsUsedCsv = allEmails,
          currentStatus = "Alerted",
          visitedUrlsCsv = "portal.corp/welcome, corp.intranet/docs"
        )
      )

      return AuthResult(
        success = true,
        status = "Alerted",
        message = "Registro completado con código OTP. Monitoreo pasivo de navegación habilitado.",
        shouldAllowNavigation = true
      )
    }

    // 3. Verificación de Intentos Reiterados Fallidos
    val failedCount = (existingSession?.failedLoginAttempts ?: 0) + 1
    if (passwordAttempt != "CorpSecure2026!" && otpCode != "948210") {
      val isLocked = failedCount >= 3
      val newStatus = if (isLocked) "Blocked" else "Normal"

      eventDao.insertEvent(
        ForensicEventEntity(
          dateFormatted = now,
          status = newStatus,
          severity = if (isLocked) "HIGH" else "LOW",
          category = "AUTH_FAILED",
          title = if (isLocked) "Cuenta Inhabilitada por Intentos Reiterados" else "Fallo de Autenticación",
          description = "Intento #$failedCount fallido para '$email'. ${if (isLocked) "Email deshabilitado pero MAC $mac se mantiene en navegación auditada." else "Esperando credenciales correctas."}",
          sourceIp = ip,
          macAddress = mac,
          associatedEmail = email,
          mitreTechnique = "T1110 - Brute Force (Credential Stuffing)"
        )
      )

      sessionDao.insertOrUpdate(
        (existingSession ?: MonitoredSessionEntity(macAddress = mac, ipAddress = ip)).copy(
          ipAddress = ip,
          lastActivity = System.currentTimeMillis(),
          failedLoginAttempts = failedCount,
          isEmailDisabled = isLocked,
          currentStatus = if (isLocked) "Alerted" else "Normal"
        )
      )

      return AuthResult(
        success = false,
        status = if (isLocked) "Blocked" else "Normal",
        message = if (isLocked) "Cuenta inhabilitada. Su MAC permanece conectada para soporte técnico." else "Credenciales incorrectas (Intento $failedCount/3).",
        shouldAllowNavigation = true // Mantener navegación abierta para auditar el pivoteo
      )
    }

    // 4. Autenticación Exitosa Normal
    eventDao.insertEvent(
      ForensicEventEntity(
        dateFormatted = now,
        status = "Normal",
        severity = "LOW",
        category = "AUTH_SUCCESS",
        title = "Autenticación Válida en Honeygate",
        description = "Acceso verificado para '$email' desde $ip ($mac). Código OTP 2FA validado con éxito.",
        sourceIp = ip,
        macAddress = mac,
        associatedEmail = email,
        mitreTechnique = "T1078 - Valid Accounts"
      )
    )

    sessionDao.insertOrUpdate(
      (existingSession ?: MonitoredSessionEntity(macAddress = mac, ipAddress = ip)).copy(
        ipAddress = ip,
        lastActivity = System.currentTimeMillis(),
        emailsUsedCsv = if (existingSession?.emailsUsedCsv.isNullOrBlank()) email else existingSession!!.emailsUsedCsv,
        currentStatus = "Normal"
      )
    )

    return AuthResult(
      success = true,
      status = "Normal",
      message = "Autenticación exitosa. Bienvenido al portal corporativo.",
      shouldAllowNavigation = true
    )
  }

  /**
   * Inicializa la base de datos con eventos de ejemplo si se encuentra vacía.
   */
  suspend fun preseedInitialDataIfEmpty() {
    val initialConfig = HoneygateConfigEntity(
      id = 1,
      gateMode = 1,
      companyName = "AeroSec Global Defense Corp",
      primaryColorHex = "#00FF66",
      accentColorHex = "#00D4FF",
      compromisedAreas = "Finanzas & SWIFT Gateway, Infraestructura Cloud DevOps",
      canaryUsersCsv = "admin_sec@aerosec.corp, jdoe_dev@aerosec.corp, cfo_pay@aerosec.corp"
    )
    configDao.saveConfig(initialConfig)

    // Crear eventos forenses representativos con estados Blocked, Alerted y Normal
    val sampleEvents = listOf(
      ForensicEventEntity(
        timestamp = System.currentTimeMillis() - 120000,
        dateFormatted = "18:42:10",
        status = "Blocked",
        severity = "CRITICAL",
        category = "RATE_LIMIT_PIVOTING",
        title = "Pivoteo Saliente Mitigado (Undahwoar Honeywall)",
        description = "Host 198.51.100.42 emitió 14 tramas TCP en 60 segundos. Se ejecutó llamada nativa shutdown(SHUT_RDWR) y corte perimetral de descriptor.",
        sourceIp = "198.51.100.42",
        macAddress = "08:00:27:fa:31:0a",
        mitreTechnique = "T1046 - Network Service Discovery",
        isCorrelated = true
      ),
      ForensicEventEntity(
        timestamp = System.currentTimeMillis() - 90000,
        dateFormatted = "18:44:25",
        status = "Alerted",
        severity = "HIGH",
        category = "SQL_INJECTION",
        title = "Inyección SQL en Formulario de Login",
        description = "Intento de elusión de autenticación con payload: 'admin' OR '1'='1' --. MAC vinculada a 2 IPs dinámicas en rango DHCP.",
        sourceIp = "192.168.1.105",
        macAddress = "52:54:00:12:34:56",
        associatedEmail = "admin@aerosec.corp",
        mitreTechnique = "T1190 - Exploit Public-Facing Application (SQLi)",
        rawPayload = "'admin' OR '1'='1' --",
        isCorrelated = true
      ),
      ForensicEventEntity(
        timestamp = System.currentTimeMillis() - 60000,
        dateFormatted = "18:48:02",
        status = "Alerted",
        severity = "MEDIUM",
        category = "MULTI_USER_MAC",
        title = "Correlación Anómala: 3 Correos en Misma MAC",
        description = "La MAC 00:1a:2b:3c:4d:5e registró los usuarios: [operador1@corp, audit@corp, root_test@corp]. Monitoreo pasivo de navegación activo.",
        sourceIp = "172.16.4.88",
        macAddress = "00:1a:2b:3c:4d:5e",
        associatedEmail = "root_test@corp",
        mitreTechnique = "T1078 - Valid Accounts"
      ),
      ForensicEventEntity(
        timestamp = System.currentTimeMillis() - 30000,
        dateFormatted = "18:51:15",
        status = "Normal",
        severity = "LOW",
        category = "AUTH_SUCCESS",
        title = "Registro Legítimo con Validación OTP",
        description = "Usuario 'jmartinez@aerosec.corp' validó código OTP 2FA de 6 dígitos. Parámetros IP/MAC nominales.",
        sourceIp = "10.0.2.15",
        macAddress = "00:50:56:c0:00:08",
        associatedEmail = "jmartinez@aerosec.corp",
        mitreTechnique = "T1078 - Valid Accounts"
      )
    )

    eventDao.insertAll(sampleEvents)

    val sampleSessions = listOf(
      MonitoredSessionEntity(
        macAddress = "08:00:27:fa:31:0a",
        ipAddress = "198.51.100.42",
        durationSeconds = 120,
        emailsUsedCsv = "attacker_scan@mail.com",
        isMacBlocked = true,
        outboundRequestsCount = 14,
        detectedAnomaliesCsv = "RATE_LIMIT_EXCEEDED",
        currentStatus = "Blocked"
      ),
      MonitoredSessionEntity(
        macAddress = "52:54:00:12:34:56",
        ipAddress = "192.168.1.105",
        durationSeconds = 480,
        emailsUsedCsv = "admin@aerosec.corp, test_pentest@gmail.com",
        isMacBlocked = false,
        failedLoginAttempts = 3,
        isEmailDisabled = true,
        outboundRequestsCount = 6,
        visitedUrlsCsv = "portal.corp/login, intranet.corp/secret_docs",
        detectedAnomaliesCsv = "SQLI_ATTEMPT, MULTI_EMAIL_MAC",
        currentStatus = "Alerted"
      ),
      MonitoredSessionEntity(
        macAddress = "00:50:56:c0:00:08",
        ipAddress = "10.0.2.15",
        durationSeconds = 940,
        emailsUsedCsv = "jmartinez@aerosec.corp",
        isMacBlocked = false,
        currentStatus = "Normal"
      )
    )

    sampleSessions.forEach { sessionDao.insertOrUpdate(it) }
  }
}

data class AuthResult(
  val success: Boolean,
  val status: String,
  val message: String,
  val shouldAllowNavigation: Boolean
)
