package com.example.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.local.HoneyGateDatabase
import com.example.data.local.entity.ForensicEvent
import com.example.data.local.entity.HoneygateConfigEntity
import com.example.data.local.entity.MonitoredSessionEntity
import com.example.data.repository.HoneyGateRepository
import com.example.data.repository.Mode1AuthResult
import com.example.data.repository.Mode2ActionResult
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class HoneyGateViewModel(application: Application) : AndroidViewModel(application) {
  private val database = HoneyGateDatabase.getInstance(application)
  private val repository = HoneyGateRepository(
    database.forensicEventDao(),
    database.monitoredSessionDao(),
    database.honeygateConfigDao()
  )

  // Filtro seleccionado: "All", "Blocked", "Alerted", "Normal"
  private val _selectedFilter = MutableStateFlow("All")
  val selectedFilter: StateFlow<String> = _selectedFilter.asStateFlow()

  // Búsqueda de texto
  private val _searchQuery = MutableStateFlow("")
  val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

  // Lista base de eventos persistidos en Room
  val rawEvents: StateFlow<List<ForensicEvent>> = repository.allEvents
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

  // Lista reactiva filtrada por tipo de evento y búsqueda
  val eventsList: StateFlow<List<ForensicEvent>> = combine(
    rawEvents,
    _selectedFilter,
    _searchQuery
  ) { events, filter, query ->
    events.filter { event ->
      val matchesFilter = if (filter == "All") true else event.eventType.equals(filter, ignoreCase = true)
      val matchesQuery = if (query.isBlank()) true else {
        event.description.contains(query, ignoreCase = true) ||
        event.sourceIp.contains(query, ignoreCase = true) ||
        event.macAddress.contains(query, ignoreCase = true) ||
        event.deviceId.contains(query, ignoreCase = true) ||
        event.mitreTechnique.contains(query, ignoreCase = true) ||
        (event.honeytokenTouched?.contains(query, ignoreCase = true) == true)
      }
      matchesFilter && matchesQuery
    }
  }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

  // Sesiones Monitoreadas con device_id compuesto
  val sessionsList: StateFlow<List<MonitoredSessionEntity>> = repository.allSessions
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

  // Configuración de los 3 Modos de HoneyGate
  val honeygateConfig: StateFlow<HoneygateConfigEntity> = repository.honeygateConfig
    .map { it ?: HoneygateConfigEntity() }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), HoneygateConfigEntity())

  // Resultados de interacción en los Modos
  private val _mode1Result = MutableStateFlow<Mode1AuthResult?>(null)
  val mode1Result: StateFlow<Mode1AuthResult?> = _mode1Result.asStateFlow()

  // Desafío OTP numérico por email (Portal Cautivo HoneyGate)
  private val _otpChallenge = MutableStateFlow<com.example.data.repository.OtpChallenge?>(null)
  val otpChallenge: StateFlow<com.example.data.repository.OtpChallenge?> = _otpChallenge.asStateFlow()

  // Resultado de prueba de Inyección SQL (Alerta al Admin)
  private val _sqlInjectionResult = MutableStateFlow<com.example.data.repository.SqlInjectionResult?>(null)
  val sqlInjectionResult: StateFlow<com.example.data.repository.SqlInjectionResult?> = _sqlInjectionResult.asStateFlow()

  private val _mode2Result = MutableStateFlow<Mode2ActionResult?>(null)
  val mode2Result: StateFlow<Mode2ActionResult?> = _mode2Result.asStateFlow()

  private val _redTeamTerminalHistory = MutableStateFlow(
    listOf(
      "redteam@honeygate:~$ id",
      "uid=1001(cfo_canary) gid=1001(canary_finance) groups=1001(finance)",
      "redteam@honeygate:~$ sudo -l",
      "(ALL) NOPASSWD: /usr/bin/service_emulator"
    )
  )
  val redTeamTerminalHistory: StateFlow<List<String>> = _redTeamTerminalHistory.asStateFlow()

  private val _escalationLevel = MutableStateFlow("Nivel 1: Acceso Inicial Canary")
  val escalationLevel: StateFlow<String> = _escalationLevel.asStateFlow()

  // Contadores reactivos
  val blockedCount: StateFlow<Int> = rawEvents.map { it.count { e -> e.eventType == "Blocked" } }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)
  val alertedCount: StateFlow<Int> = rawEvents.map { it.count { e -> e.eventType == "Alerted" } }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)
  val normalCount: StateFlow<Int> = rawEvents.map { it.count { e -> e.eventType == "Normal" } }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

  init {
    viewModelScope.launch {
      repository.preseedInitialDataIfEmpty()
    }
  }

  fun setFilter(filter: String) {
    _selectedFilter.value = filter
  }

  fun setSearchQuery(query: String) {
    _searchQuery.value = query
  }

  fun clearMode1Result() {
    _mode1Result.value = null
  }

  fun requestOtp(email: String, ip: String, mac: String) {
    val randomPin = (100000..999999).random().toString()
    val devId = repository.calculateCompositeDeviceId(mac)
    _otpChallenge.value = com.example.data.repository.OtpChallenge(
      email = email,
      code = randomPin,
      deviceId = devId,
      timestamp = System.currentTimeMillis()
    )
  }

  fun dismissOtpChallenge() {
    _otpChallenge.value = null
  }

  fun verifyOtpAndRegister(enteredCode: String, ip: String, mac: String): Boolean {
    val challenge = _otpChallenge.value ?: return false
    return if (enteredCode.trim() == challenge.code) {
      registerMode1(challenge.email, ip, mac)
      _otpChallenge.value = null
      true
    } else {
      false
    }
  }

  fun triggerSqlInjectionTest(payload: String, ip: String, mac: String) {
    viewModelScope.launch {
      val res = repository.processSqlInjectionProbe(payload, ip, mac)
      _sqlInjectionResult.value = res
    }
  }

  fun clearSqlInjectionResult() {
    _sqlInjectionResult.value = null
  }

  fun updateCompanyBranding(companyName: String, primaryColorHex: String, accentColorHex: String) {
    viewModelScope.launch {
      val current = honeygateConfig.value
      repository.saveHoneygateConfig(
        current.copy(
          companyName = companyName,
          primaryColorHex = primaryColorHex,
          accentColorHex = accentColorHex
        )
      )
    }
  }

  fun registerMode1(email: String, ip: String, mac: String) {
    viewModelScope.launch {
      val result = repository.processMode1Registration(email, ip, mac)
      _mode1Result.value = result
    }
  }

  fun runRedTeamCommand(canaryUser: String, command: String) {
    viewModelScope.launch {
      val result = repository.processMode2RedTeamAction(canaryUser, command)
      _mode2Result.value = result
      _escalationLevel.value = result.escalationLevel
      _redTeamTerminalHistory.value = _redTeamTerminalHistory.value + listOf("redteam@honeygate:~$ $command", result.commandOutput)
    }
  }

  fun blockMacConfirmed(mac: String, deviceId: String) {
    viewModelScope.launch {
      repository.updateMacBlockStatus(mac, deviceId, blocked = true)
    }
  }

  fun unblockMacConfirmed(mac: String, deviceId: String) {
    viewModelScope.launch {
      repository.updateMacBlockStatus(mac, deviceId, blocked = false)
    }
  }

  fun saveConfig(config: HoneygateConfigEntity) {
    viewModelScope.launch {
      repository.saveHoneygateConfig(config)
    }
  }

  fun generateAuditReport(): String {
    val events = rawEvents.value
    val sessions = sessionsList.value
    val config = honeygateConfig.value
    val date = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())

    val blocked = events.count { it.eventType == "Blocked" }
    val alerted = events.count { it.eventType == "Alerted" }
    val normal = events.count { it.eventType == "Normal" }

    return buildString {
      appendLine("================================================================================")
      appendLine(" HONEYGATE // INFORME DE AUDITORÍA Y TELEMETRÍA DE CIBERSEGURIDAD DEFENSIVA")
      appendLine("================================================================================")
      appendLine("Fecha de Emisión : $date")
      appendLine("Modo Activo      : Modo ${config.gateMode} (${when(config.gateMode) { 1 -> "Portal Cautivo Trazable"; 2 -> "Honeypot Red Team Assume-Breach"; else -> "Mixto Unificado" }})")
      appendLine("Empresa Objetivo : ${config.companyName}")
      appendLine("Marco Legal      : Cumplimiento Ley 25.326 (Protección Datos) y Ley 26.388 (Delitos Informáticos)")
      appendLine("Estado Global    : $blocked Bloqueados | $alerted En Observación/Alerta | $normal Nominales")
      appendLine("--------------------------------------------------------------------------------\n")

      appendLine("1. INVARIANTES DE SEGURIDAD OPERATIVOS")
      appendLine(" • Invariante 1: Identificación por Fingerprint Compuesto (device_id) activa (anti MAC spoofing/NAT).")
      appendLine(" • Invariante 2: Contención estricta de salida (${config.egressMode}) con lista blanca de destinos.")
      appendLine(" • Invariante 3: Honeytokens sembrados (${config.honeytokenUsersCsv}) con alerta inmediata al contacto.")
      appendLine(" • Invariante 4: Consentimiento explícito de metadatos habilitado: ${config.legalConsentBannerEnabled}.")
      appendLine(" • Invariante 5: Acciones de bloqueo sujetas a confirmación explícita del operador.\n")

      appendLine("2. ESQUEMA DE DATOS Y CORRELACIÓN FORENSE (ORIGEN <-> DESTINO)")
      sessions.forEach { s ->
        appendLine(" • [device_id: ${s.deviceId}]")
        appendLine("   - Origen: MAC=${s.macAddress} | IP=${s.ipAddress} | Dispositivo=${s.deviceType}")
        appendLine("   - Fingerprints: JA3=${s.ja3Fingerprint.take(20)}... | DHCP=${s.dhcpFingerprint}")
        appendLine("   - Sesión: Lease=${s.dhcpLeaseSeconds}s | Duración=${s.durationSeconds}s | En Observación: ${s.isInObservation}")
        appendLine("   - Correos/Identidades: ${s.emailsUsedCsv}")
        appendLine("   - Estado de Contención: ${s.currentStatus} (Bloqueado: ${s.isMacBlocked})")
        appendLine("   - Tráfico Auditado (URLs): ${s.visitedUrlsCsv.ifEmpty { "N/A" }}\n")
      }

      appendLine("3. TÁCTICAS Y TÉCNICAS MITRE ATT&CK IDENTIFICADAS")
      events.groupBy { it.mitreTechnique }.forEach { (tech, list) ->
        appendLine(" • [${list.size} eventos] $tech")
      }
      appendLine()

      appendLine("4. REGISTRO CRONOLÓGICO DE EVENTOS FORENSES (ÚLTIMOS 10)")
      events.take(10).forEach { e ->
        appendLine(" [${e.dateFormatted.ifEmpty { SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(e.timestamp)) }}] [${e.eventType.uppercase()}] [${e.severity}] ${e.category}")
        appendLine("   Descripción: ${e.description}")
        appendLine("   Origen: ${e.sourceIp} (${e.macAddress}) | device_id: ${e.deviceId}")
        e.honeytokenTouched?.let { appendLine("   [!] Honeytoken Afectado: $it") }
        appendLine("   Técnica MITRE: ${e.mitreTechnique}\n")
      }

      appendLine("5. RECOMENDACIONES DE ENDURECIMIENTO Y MITIGACIÓN (BLUE TEAM)")
      appendLine(" 1. Aplicar reglas de velocidad en DHCP para aislar dispositivos en observación tras registrar múltiples identidades.")
      appendLine(" 2. Restringir la resolución DNS hacia dominios no autorizados redirigiendo tráfico anómalo al Sinkhole de HoneyGate.")
      appendLine(" 3. Rotar periódicamente los Honeytokens sembrados en sectores sensibles (Finanzas y DevOps).")
      appendLine("================================================================================")
    }
  }

  fun clearAllEvents() {
    viewModelScope.launch {
      repository.clearAllEvents()
    }
  }
}
