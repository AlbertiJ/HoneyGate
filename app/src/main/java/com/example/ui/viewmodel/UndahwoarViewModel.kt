package com.example.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.local.UndahwoarDatabase
import com.example.data.local.entity.ForensicEventEntity
import com.example.data.local.entity.HoneygateConfigEntity
import com.example.data.local.entity.MonitoredSessionEntity
import com.example.data.repository.AuthResult
import com.example.data.repository.UndahwoarRepository
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class UndahwoarViewModel(application: Application) : AndroidViewModel(application) {
  private val database = UndahwoarDatabase.getInstance(application)
  private val repository = UndahwoarRepository(
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

  // Lista base de eventos desde Room
  val rawEvents: StateFlow<List<ForensicEventEntity>> = repository.allEvents
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

  // Lista filtrada reactiva
  val eventsList: StateFlow<List<ForensicEventEntity>> = combine(
    rawEvents,
    _selectedFilter,
    _searchQuery
  ) { events, filter, query ->
    events.filter { event ->
      val matchesFilter = if (filter == "All") true else event.status.equals(filter, ignoreCase = true)
      val matchesQuery = if (query.isBlank()) true else {
        event.title.contains(query, ignoreCase = true) ||
        event.description.contains(query, ignoreCase = true) ||
        event.sourceIp.contains(query, ignoreCase = true) ||
        event.macAddress.contains(query, ignoreCase = true) ||
        (event.associatedEmail?.contains(query, ignoreCase = true) == true) ||
        event.mitreTechnique.contains(query, ignoreCase = true)
      }
      matchesFilter && matchesQuery
    }
  }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

  // Sesiones Monitoreadas
  val sessionsList: StateFlow<List<MonitoredSessionEntity>> = repository.allSessions
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

  // Configuración de la Puerta de Miel / Honeygate
  val honeygateConfig: StateFlow<HoneygateConfigEntity> = repository.honeygateConfig
    .map { it ?: HoneygateConfigEntity() }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), HoneygateConfigEntity())

  // Estado del último intento de autenticación en Honeygate
  private val _lastAuthResult = MutableStateFlow<AuthResult?>(null)
  val lastAuthResult: StateFlow<AuthResult?> = _lastAuthResult.asStateFlow()

  // Historial de comandos ejecutados en el laboratorio de Red Team (Opción 2)
  private val _redTeamTerminalHistory = MutableStateFlow(
    listOf(
      "redteam@honeygate:~$ id",
      "uid=1001(guest) gid=1001(guest) groups=1001(guest)",
      "redteam@honeygate:~$ sudo -l",
      "[!] Host alert triggered: Intento de enumeración de privilegios sudo (T1069.001)"
    )
  )
  val redTeamTerminalHistory: StateFlow<List<String>> = _redTeamTerminalHistory.asStateFlow()

  // Nivel de escalación detectado para Red Team
  private val _escalationLevel = MutableStateFlow("Nivel 1: Acceso Inicial (Usuario Restringido)")
  val escalationLevel: StateFlow<String> = _escalationLevel.asStateFlow()

  // Estadísticas de eventos
  val blockedCount: StateFlow<Int> = rawEvents.map { it.count { e -> e.status == "Blocked" } }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)
  val alertedCount: StateFlow<Int> = rawEvents.map { it.count { e -> e.status == "Alerted" } }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)
  val normalCount: StateFlow<Int> = rawEvents.map { it.count { e -> e.status == "Normal" } }
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

  fun clearAuthResult() {
    _lastAuthResult.value = null
  }

  fun submitHoneygateAuth(
    ip: String,
    mac: String,
    email: String,
    passwordAttempt: String,
    otpCode: String?
  ) {
    viewModelScope.launch {
      val result = repository.processHoneygateAuthAttempt(ip, mac, email, passwordAttempt, otpCode)
      _lastAuthResult.value = result
    }
  }

  fun blockMac(mac: String) {
    viewModelScope.launch {
      repository.updateMacBlockStatus(mac, blocked = true)
    }
  }

  fun unblockMac(mac: String) {
    viewModelScope.launch {
      repository.updateMacBlockStatus(mac, blocked = false)
    }
  }

  fun saveConfig(config: HoneygateConfigEntity) {
    viewModelScope.launch {
      repository.saveHoneygateConfig(config)
    }
  }

  fun simulateRedTeamCommand(command: String, canaryUser: String) {
    val now = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
    val cmd = command.trim()
    val output = when {
      cmd.contains("cat /etc/shadow") || cmd.contains("shadow") -> {
        _escalationLevel.value = "Nivel 3: Acceso a Credenciales Privilegiadas (CRÍTICO)"
        viewModelScope.launch {
          repository.insertEvent(
            ForensicEventEntity(
              dateFormatted = now,
              status = "Blocked",
              severity = "CRITICAL",
              category = "REDTEAM_EXPLOIT",
              title = "Red Team: Intento de Volcado de Hashes (/etc/shadow)",
              description = "Canary User comprometido: $canaryUser. Ejecución de '$cmd'. El sistema emuló un archivo señuelo con Honeytokens inyectados.",
              sourceIp = "10.0.8.44",
              macAddress = "aa:bb:cc:dd:ee:01",
              associatedEmail = canaryUser,
              mitreTechnique = "T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow"
            )
          )
        }
        "root:\$6\$fakeSalt\$HoneyTokenHashK8J9...:19420:0:99999:7:::"
      }
      cmd.contains("sudo") || cmd.contains("su -") -> {
        _escalationLevel.value = "Nivel 2: Intento de Escalación de Privilegios"
        viewModelScope.launch {
          repository.insertEvent(
            ForensicEventEntity(
              dateFormatted = now,
              status = "Alerted",
              severity = "HIGH",
              category = "REDTEAM_EXPLOIT",
              title = "Red Team: Intento de Elevación con Sudo",
              description = "Canary User $canaryUser intentó romper escalamiento: '$cmd'. Honeygate interceptó el descriptor simulando respuesta restringida.",
              sourceIp = "10.0.8.44",
              macAddress = "aa:bb:cc:dd:ee:01",
              associatedEmail = canaryUser,
              mitreTechnique = "T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching"
            )
          )
        }
        "[sudo] password for $canaryUser: \n[!] Permiso denegado. Intento reportado a Undahwoar Core."
      }
      cmd.contains("netstat") || cmd.contains("nmap") -> {
        "Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN (Honeypot SSH)\ntcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN (Emulated MySQL)\ntcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN (Emulated Apache)"
      }
      else -> {
        "Comando '$cmd' procesado por la consola de emulación segura de Undahwoar."
      }
    }

    _redTeamTerminalHistory.value = _redTeamTerminalHistory.value + listOf("redteam@honeygate:~$ $cmd", output)
  }

  fun generateBlueTeamReport(): String {
    val events = rawEvents.value
    val sessions = sessionsList.value
    val date = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())

    val blocked = events.count { it.status == "Blocked" }
    val alerted = events.count { it.status == "Alerted" }
    val normal = events.count { it.status == "Normal" }

    return buildString {
      appendLine("================================================================================")
      appendLine(" INFORME TÉCNICO DE CIBERSEGURIDAD DEFENSIVA // BLUE TEAM - UNDAHWOAR HONEYWALL")
      appendLine("================================================================================")
      appendLine("Fecha de Emisión : $date")
      appendLine("Clasificación    : CONFIDENCIAL // TLP:AMBER")
      appendLine("Entorno Auditado : Red Perimetral y Puerta de Miel (Honeygate Non-Root)")
      appendLine("Estado Global    : $blocked Bloqueados | $alerted En Alerta Activa | $normal Nominales")
      appendLine("--------------------------------------------------------------------------------\n")

      appendLine("1. RESUMEN EJECUTIVO")
      appendLine("Se ha desplegado el framework Undahwoar con persistencia local en Room y análisis de")
      appendLine("correlación IP/MAC. Se identificaron vectores de ataque correspondientes a Inyección SQL,")
      appendLine("agregación ilícita de múltiples cuentas bajo una misma dirección física MAC, e intentos")
      appendLine("de pivoteo de red contenidos mediante desconexión nativa shutdown(SHUT_RDWR).\n")

      appendLine("2. MATRIZ DE TÁCTICAS Y TÉCNICAS MITRE ATT&CK IDENTIFICADAS")
      events.groupBy { it.mitreTechnique }.forEach { (technique, list) ->
        appendLine(" • [${list.size} ocurrencias] $technique")
      }
      appendLine()

      appendLine("3. CORRELACIÓN FORENSE DE SESIONES (IP / MAC / IDENTIDADES)")
      sessions.forEach { s ->
        appendLine(" • MAC: ${s.macAddress} <-> IP: ${s.ipAddress}")
        appendLine("   - Correos Asociados: ${s.emailsUsedCsv}")
        appendLine("   - Estado de Contención: ${s.currentStatus} (Bloqueada: ${s.isMacBlocked}, Email Deshabilitado: ${s.isEmailDisabled})")
        appendLine("   - Anomalías: ${s.detectedAnomaliesCsv}")
      }
      appendLine()

      appendLine("4. LÍNEA DE TIEMPO FORENSE (TIMELINE RECIENTE)")
      events.take(8).forEach { e ->
        appendLine(" [${e.dateFormatted}] [${e.status.uppercase()}] [${e.severity}] ${e.title}")
        appendLine("   Detalle: ${e.description}")
        appendLine("   Origen: ${e.sourceIp} (${e.macAddress}) | Técnica: ${e.mitreTechnique}\n")
      }

      appendLine("5. RECOMENDACIONES DE ENDURECIMIENTO (BLUE TEAM HARDENING)")
      appendLine(" 1. Aplicar reglas WAF estrictas para parametrización de consultas preparadas (evitar SQLi).")
      appendLine(" 2. Aislar en VLAN defensiva a los dispositivos con múltiples MACs virtuales.")
      appendLine(" 3. Mantener activos los Honeytokens en archivos señuelo para alerta temprana de compromiso.")
      appendLine("================================================================================")
    }
  }

  fun clearAllEvents() {
    viewModelScope.launch {
      repository.clearAllEvents()
    }
  }
}
