package com.example.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.local.HoneyGateDatabase
import com.example.data.local.entity.ForensicEvent
import com.example.data.local.entity.HoneygateConfigEntity
import com.example.data.local.entity.MonitoredSessionEntity
import com.example.data.remote.DaemonConfigUpdate
import com.example.data.remote.DaemonStatus
import com.example.data.repository.HoneyGateRepository
import com.example.data.repository.Mode1AuthResult
import com.example.data.repository.Mode2ActionResult
import com.example.data.repository.OtpChallenge
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

  private val _selectedFilter = MutableStateFlow("All")
  val selectedFilter: StateFlow<String> = _selectedFilter.asStateFlow()

  private val _searchQuery = MutableStateFlow("")
  val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

  val honeygateConfig: StateFlow<HoneygateConfigEntity> = repository.honeygateConfig
    .map { it ?: HoneygateConfigEntity() }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), HoneygateConfigEntity())

  // Filtra caché según esté o no activo el Modo DEMO
  val rawEvents: StateFlow<List<ForensicEvent>> = combine(
    repository.allEvents,
    honeygateConfig
  ) { events, cfg ->
    if (cfg.demoModeEnabled) events else events.filter { !it.isDemo }
  }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

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
          event.rawEventType.contains(query, ignoreCase = true) ||
          event.mitreTechnique.contains(query, ignoreCase = true) ||
          (event.honeytokenTouched?.contains(query, ignoreCase = true) == true)
      }
      matchesFilter && matchesQuery
    }
  }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

  val sessionsList: StateFlow<List<MonitoredSessionEntity>> = combine(
    repository.allSessions,
    honeygateConfig
  ) { sessions, cfg ->
    if (cfg.demoModeEnabled) sessions else sessions.filter { !it.isDemo }
  }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

  // Estado LIVE del daemon y paginación real (/api/sessions y /api/events)
  private val _daemonStatus = MutableStateFlow<DaemonStatus?>(null)
  val daemonStatus: StateFlow<DaemonStatus?> = _daemonStatus.asStateFlow()

  private val _isSyncingDaemon = MutableStateFlow(false)
  val isSyncingDaemon: StateFlow<Boolean> = _isSyncingDaemon.asStateFlow()

  private val _daemonSyncMessage = MutableStateFlow<String?>(null)
  val daemonSyncMessage: StateFlow<String?> = _daemonSyncMessage.asStateFlow()

  private val _sessionsTotal = MutableStateFlow(0)
  val sessionsTotal: StateFlow<Int> = _sessionsTotal.asStateFlow()

  private val _eventsTotal = MutableStateFlow(0)
  val eventsTotal: StateFlow<Int> = _eventsTotal.asStateFlow()

  // Estado DEMO opcional (apagado por defecto)
  private val _mode1Result = MutableStateFlow<Mode1AuthResult?>(null)
  val mode1Result: StateFlow<Mode1AuthResult?> = _mode1Result.asStateFlow()

  private val _otpChallenge = MutableStateFlow<OtpChallenge?>(null)
  val otpChallenge: StateFlow<OtpChallenge?> = _otpChallenge.asStateFlow()

  private val _mode2Result = MutableStateFlow<Mode2ActionResult?>(null)
  val mode2Result: StateFlow<Mode2ActionResult?> = _mode2Result.asStateFlow()

  private val _redTeamTerminalHistory = MutableStateFlow<List<String>>(emptyList())
  val redTeamTerminalHistory: StateFlow<List<String>> = _redTeamTerminalHistory.asStateFlow()

  private val _escalationLevel = MutableStateFlow("Sin actividad")
  val escalationLevel: StateFlow<String> = _escalationLevel.asStateFlow()

  val blockedCount: StateFlow<Int> = rawEvents.map { it.count { e -> e.eventType == "Blocked" } }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)
  val alertedCount: StateFlow<Int> = rawEvents.map { it.count { e -> e.eventType == "Alerted" } }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)
  val normalCount: StateFlow<Int> = rawEvents.map { it.count { e -> e.eventType == "Normal" } }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

  init {
    viewModelScope.launch {
      repository.preseedInitialDataIfEmpty()
      val cfg = repository.getConfigOnce() ?: honeygateConfig.value
      val token = cfg.daemonAuthToken.trim()
      if (token.isNotEmpty() && cfg.daemonSyncEnabled) {
        syncDaemonData()
      } else {
        checkDaemonHealth()
      }
    }
  }

  fun checkDaemonHealth() {
    viewModelScope.launch {
      val config = repository.getConfigOnce() ?: honeygateConfig.value
      val baseUrl = config.daemonBaseUrl.ifBlank { "http://10.0.2.2:8888" }
      val token = config.daemonAuthToken.trim()
      _daemonStatus.value = repository.checkDaemonHealth(baseUrl, token)
    }
  }

  fun syncDaemonData(limit: Int = 50, offset: Int = 0) {
    viewModelScope.launch {
      val config = repository.getConfigOnce() ?: honeygateConfig.value
      val baseUrl = config.daemonBaseUrl.ifBlank { "http://10.0.2.2:8888" }
      val token = config.daemonAuthToken.trim()
      if (token.isEmpty()) {
        _daemonSyncMessage.value = "Configurá el token"
        _daemonStatus.value = DaemonStatus(
          online = false,
          hostUrl = baseUrl,
          errorMessage = "Configurá el token"
        )
        return@launch
      }
      _isSyncingDaemon.value = true
      val result = repository.syncWithDaemon(baseUrl, token, limit = limit, offset = offset)
      _isSyncingDaemon.value = false
      result.fold(
        onSuccess = { summary ->
          _sessionsTotal.value = summary.sessionsTotal
          _eventsTotal.value = summary.eventsTotal
          _daemonSyncMessage.value = summary.message
        },
        onFailure = { err ->
          _daemonSyncMessage.value = "Sin conexión: ${err.localizedMessage}"
        }
      )
      _daemonStatus.value = repository.checkDaemonHealth(baseUrl, token)
    }
  }

  fun updateDaemonConnectionConfig(baseUrl: String, token: String, enabled: Boolean) {
    viewModelScope.launch {
      val current = repository.getConfigOnce() ?: honeygateConfig.value
      val cleanUrl = baseUrl.trim()
      val cleanToken = token.trim()
      val updated = current.copy(
        daemonBaseUrl = cleanUrl,
        daemonAuthToken = cleanToken,
        daemonSyncEnabled = enabled
      )
      repository.saveHoneygateConfig(updated)
      if (cleanToken.isEmpty()) {
        _daemonStatus.value = DaemonStatus(
          online = false,
          hostUrl = cleanUrl,
          errorMessage = "Configurá el token"
        )
        return@launch
      }
      _daemonStatus.value = repository.checkDaemonHealth(cleanUrl, cleanToken)
      if (_daemonStatus.value?.online == true && enabled) {
        syncDaemonData()
      }
    }
  }

  /**
   * Envía cambios operativos reales al daemon mediante PUT /api/config.
   */
  fun pushConfigToDaemon(update: DaemonConfigUpdate) {
    viewModelScope.launch {
      val cfg = repository.getConfigOnce() ?: honeygateConfig.value
      if (cfg.demoModeEnabled && cfg.daemonAuthToken.isBlank()) {
        val localDemo = cfg.copy(
          gateMode = update.mode ?: cfg.gateMode,
          portalEnabled = update.portalEnabled ?: cfg.portalEnabled,
          honeypotEnabled = update.honeypotEnabled ?: cfg.honeypotEnabled,
          maxOutboundPerMinute = update.maxOutboundPerMinute ?: cfg.maxOutboundPerMinute,
          retentionDays = update.retentionDays ?: cfg.retentionDays
        )
        repository.saveHoneygateConfig(localDemo)
        _daemonSyncMessage.value = "[DEMO] Cambio aplicado solo en caché local."
        return@launch
      }

      val result = repository.pushDaemonConfig(update)
      result.fold(
        onSuccess = { dto ->
          _daemonSyncMessage.value = "Configuración guardada en daemon (modo=${dto.mode})."
        },
        onFailure = { err ->
          _daemonSyncMessage.value = "No se pudo actualizar el daemon: ${err.localizedMessage}"
        }
      )
    }
  }

  fun setOperatingMode(mode: Int) {
    val portalOn = mode == 1 || mode == 3
    val honeypotOn = mode == 2 || mode == 3
    pushConfigToDaemon(
      DaemonConfigUpdate(
        mode = mode,
        portalEnabled = portalOn,
        honeypotEnabled = honeypotOn
      )
    )
  }

  fun toggleDemoMode(enabled: Boolean) {
    viewModelScope.launch {
      repository.setDemoMode(enabled)
      if (!enabled) {
        _mode1Result.value = null
        _otpChallenge.value = null
        _mode2Result.value = null
        _redTeamTerminalHistory.value = emptyList()
        _escalationLevel.value = "Sin actividad"
        _daemonSyncMessage.value = "Modo DEMO desactivado y datos ficticios eliminados."
      } else {
        _daemonSyncMessage.value = "Modo DEMO activado (solo pruebas locales, no representa tráfico real)."
      }
    }
  }

  fun observeSessionConfirmed(session: MonitoredSessionEntity, reason: String = "Marcada en observación desde panel Android") {
    viewModelScope.launch {
      val res = repository.observeDaemonSession(session, reason)
      res.fold(
        onSuccess = { updated ->
          _daemonSyncMessage.value = "Sesión #${updated.daemonSessionId ?: updated.id} marcada en observación."
          val cfg = repository.getConfigOnce()
          if (cfg != null && cfg.daemonAuthToken.isNotBlank() && !session.isDemo) {
            repository.syncWithDaemon(cfg.daemonBaseUrl, cfg.daemonAuthToken)
          }
        },
        onFailure = { err ->
          _daemonSyncMessage.value = "Error al marcar observación: ${err.localizedMessage}"
        }
      )
    }
  }

  fun isolateOrUnblockSessionConfirmed(session: MonitoredSessionEntity, blocked: Boolean) {
    viewModelScope.launch {
      val res = repository.updateSessionIsolation(session, blocked)
      res.fold(
        onSuccess = { msg ->
          _daemonSyncMessage.value = msg
          val cfg = repository.getConfigOnce()
          if (cfg != null && cfg.daemonAuthToken.isNotBlank() && !session.isDemo) {
            repository.syncWithDaemon(cfg.daemonBaseUrl, cfg.daemonAuthToken)
          }
        },
        onFailure = { err ->
          _daemonSyncMessage.value = "Error en contención: ${err.localizedMessage}"
        }
      )
    }
  }

  fun isolateIpFromEventConfirmed(ip: String, deviceId: String) {
    viewModelScope.launch {
      val res = repository.isolateIpFromEvent(ip, deviceId)
      res.fold(
        onSuccess = { msg ->
          _daemonSyncMessage.value = msg
          val cfg = repository.getConfigOnce()
          if (cfg != null && cfg.daemonAuthToken.isNotBlank()) {
            repository.syncWithDaemon(cfg.daemonBaseUrl, cfg.daemonAuthToken)
          }
        },
        onFailure = { err ->
          _daemonSyncMessage.value = "Error al aislar IP: ${err.localizedMessage}"
        }
      )
    }
  }

  fun clearDaemonMessage() {
    _daemonSyncMessage.value = null
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

  fun updateCompanyBranding(companyName: String, primaryColorHex: String, accentColorHex: String) {
    viewModelScope.launch {
      val current = repository.getConfigOnce() ?: honeygateConfig.value
      repository.saveHoneygateConfig(
        current.copy(
          companyName = companyName,
          primaryColorHex = primaryColorHex,
          accentColorHex = accentColorHex
        )
      )
    }
  }

  // Operaciones DEMO (solo funcionan cuando demoModeEnabled == true)
  fun registerDemoMode1(email: String, ip: String, mac: String) {
    viewModelScope.launch {
      _mode1Result.value = repository.runDemoMode1Registration(email, ip, mac)
    }
  }

  fun requestDemoOtp(email: String, ip: String, mac: String) {
    if (!honeygateConfig.value.demoModeEnabled) return
    val randomPin = (100000..999999).random().toString()
    val devId = repository.calculateCompositeDeviceId(mac)
    _otpChallenge.value = OtpChallenge(
      email = email,
      code = randomPin,
      deviceId = devId,
      timestamp = System.currentTimeMillis()
    )
  }

  fun dismissOtpChallenge() {
    _otpChallenge.value = null
  }

  fun verifyDemoOtpAndRegister(enteredCode: String, ip: String, mac: String): Boolean {
    val challenge = _otpChallenge.value ?: return false
    return if (enteredCode.trim() == challenge.code) {
      registerDemoMode1(challenge.email, ip, mac)
      _otpChallenge.value = null
      true
    } else {
      false
    }
  }

  fun runDemoRedTeamCommand(canaryUser: String, command: String) {
    viewModelScope.launch {
      val result = repository.runDemoRedTeamCommand(canaryUser, command)
      _mode2Result.value = result
      _escalationLevel.value = result.escalationLevel
      _redTeamTerminalHistory.value = _redTeamTerminalHistory.value + listOf("[DEMO] $ $command", result.commandOutput)
    }
  }

  fun clearAllEvents() {
    viewModelScope.launch {
      repository.clearAllEvents()
    }
  }

  fun generateAuditReport(): String {
    val events = rawEvents.value
    val sessions = sessionsList.value
    val config = honeygateConfig.value
    val status = _daemonStatus.value
    val isOnline = status?.online == true
    val date = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())

    if (!isOnline && events.isEmpty() && sessions.isEmpty()) {
      return buildString {
        appendLine("HONEYGATE // INFORME DE TELEMETRÍA")
        appendLine("Estado: Sin conexión con el daemon (${status?.errorMessage ?: "desconectado"})")
        appendLine("Caché local: vacía (sin sesiones ni eventos registrados).")
        appendLine("Conectá el daemon en el panel superior y sincronizá para obtener datos reales.")
      }
    }

    val cacheLabel = if (isOnline) {
      "Conectado al daemon (${config.daemonBaseUrl})"
    } else {
      val syncedStr = if (config.lastSyncedAtMs > 0L) {
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date(config.lastSyncedAtMs))
      } else {
        "sin sincronización previa"
      }
      "SIN CONEXIÓN — mostrando caché local ($syncedStr)"
    }

    val criticalCount = events.count { it.severity.equals("critical", true) || it.eventType == "Blocked" }
    val warningCount = events.count { it.severity.equals("warning", true) || it.eventType == "Alerted" }
    val normalCountLocal = events.size - criticalCount - warningCount

    return buildString {
      appendLine("================================================================================")
      appendLine(" HONEYGATE // RESUMEN DE TELEMETRÍA")
      if (config.demoModeEnabled) {
        appendLine(" [AVISO: MODO DEMO ACTIVO — INCLUYE DATOS LOCALES DE PRUEBA]")
      }
      appendLine("================================================================================")
      appendLine("Fecha de Vista   : $date")
      appendLine("Origen de Datos  : $cacheLabel")
      appendLine("Modo Operativo   : Modo ${config.gateMode} (portal_enabled=${config.portalEnabled}, honeypot_enabled=${config.honeypotEnabled})")
      appendLine("Retención        : ${config.retentionDays} días | Rate límite salida: ${config.maxOutboundPerMinute} req/min")
      appendLine("Resumen Eventos  : ${events.size} totales ($criticalCount críticos/bloqueados, $warningCount alertas, $normalCountLocal normales)")
      appendLine("Sesiones en Vista: ${sessions.size}")
      appendLine("--------------------------------------------------------------------------------\n")

      if (sessions.isNotEmpty()) {
        appendLine("SESIONES REGISTRADAS:")
        sessions.forEach { s ->
          appendLine(" • Session #${s.daemonSessionId ?: s.id} [${s.currentStatus}] IP=${s.ipAddress} MAC=${s.macAddress} device_id=${s.deviceId}")
          appendLine("   Destino=${s.service}:${s.destPort} | Duración=${s.durationSeconds}s | In=${s.bytesIn}B Out=${s.bytesOut}B")
          if (s.observedReason.isNotBlank()) {
            appendLine("   Motivo observación: ${s.observedReason}")
          }
        }
        appendLine()
      }

      if (events.isNotEmpty()) {
        appendLine("EVENTOS RECIENTES:")
        events.take(20).forEach { e ->
          val timeStr = e.dateFormatted.ifBlank { SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(e.timestamp)) }
          appendLine(" [$timeStr] [${e.severity.uppercase()}] ${e.rawEventType.ifBlank { e.category }}: ${e.description}")
          if (e.mitreTechnique.isNotBlank()) {
            appendLine("   MITRE: ${e.mitreTechnique}")
          }
        }
      }
      appendLine("================================================================================")
    }
  }
}
