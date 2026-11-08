package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.theme.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

data class ActiveSessionUi(
  val fd: Int,
  val ip: String,
  val port: Int,
  val mac: String,
  var outboundRate: Int,
  val connectedAgoSec: Int
)

data class ForensicAlertUi(
  val id: Long,
  val time: String,
  val severity: String, // "critical", "warning", "info"
  val title: String,
  val message: String,
  val source: String
)

data class TerminalLogUi(
  val text: String,
  val isCommand: Boolean = false,
  val color: Color = TextPrimary
)

class MainActivity : ComponentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    enableEdgeToEdge()
    setContent {
      MyApplicationTheme {
        UndahwoarAppScreen()
      }
    }
  }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UndahwoarAppScreen() {
  var selectedTab by remember { mutableIntStateOf(0) }
  val tabs = listOf(
    "Honeywall" to Icons.Default.Shield,
    "Alertas inotify" to Icons.Default.NotificationsActive,
    "Consola CLI" to Icons.Default.Terminal,
    "Laboratorio" to Icons.Default.Science
  )

  // Estados del Honeywall
  var totalConnections by remember { mutableIntStateOf(34) }
  var rateLimitViolations by remember { mutableIntStateOf(2) }
  val activeSessions = remember {
    mutableStateListOf(
      ActiveSessionUi(8, "192.168.1.105", 48210, "08:00:27:fa:31:0a", 4, 18),
      ActiveSessionUi(12, "10.0.2.15", 51920, "52:54:00:12:34:56", 2, 45),
      ActiveSessionUi(15, "172.16.4.88", 39104, "00:1a:2b:3c:4d:5e", 9, 6)
    )
  }
  val isolatedIps = remember {
    mutableStateListOf(
      "198.51.100.42" to "Pivoteo saliente excesivo (14 tramas/min)",
      "203.0.113.19" to "Aislamiento manual desde CLI"
    )
  }

  // Alertas Forenses inotify
  val alerts = remember {
    mutableStateListOf(
      ForensicAlertUi(
        1, "19:04:12", "critical",
        "Pivoteo Detectado (Honeywall)",
        "IP 198.51.100.42 superó 10 req/min -> shutdown(SHUT_RDWR) ejecutado",
        "honeywall.log"
      ),
      ForensicAlertUi(
        2, "19:02:45", "warning",
        "Failed password para 'root'",
        "Intento fallido desde 192.168.1.105:48210 en puerto emulado 2222",
        "auth.log (inotify)"
      ),
      ForensicAlertUi(
        3, "19:00:10", "info",
        "Sesión de Decepción Establecida",
        "Conexión TCP en 0.0.0.0:8080 desde 10.0.2.15",
        "cowrie.json"
      )
    )
  }

  // Consola CLI
  val terminalLogs = remember {
    mutableStateListOf(
      TerminalLogUi("Undahwoar Defensive Honeywall Core v1.0.0 - Kali Linux / WSL2", color = CyberCyan),
      TerminalLogUi("Edge-Triggered epoll activo en puertos 2222, 8080, 8443 (Non-Root)", color = CyberGreen),
      TerminalLogUi("Umbral de Contención: 10 peticiones salientes/minuto", color = WarningAmber),
      TerminalLogUi("Escriba 'help' o seleccione una sugerencia dinámica.\n", color = TextSecondary)
    )
  }

  Scaffold(
    modifier = Modifier.fillMaxSize(),
    containerColor = DarkBackground,
    topBar = {
      TopAppBar(
        colors = TopAppBarDefaults.topAppBarColors(
          containerColor = DarkSurface,
          titleContentColor = TextPrimary
        ),
        title = {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)
          ) {
            Box(
              modifier = Modifier
                .size(36.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(GreenGlow)
                .border(1.dp, CyberGreen, RoundedCornerShape(8.dp)),
              contentAlignment = Alignment.Center
            ) {
              Icon(
                imageVector = Icons.Default.Shield,
                contentDescription = "Shield",
                tint = CyberGreen,
                modifier = Modifier.size(20.dp)
              )
            }
            Column {
              Text(
                text = "UNDAHWOAR",
                fontWeight = FontWeight.Bold,
                fontSize = 17.sp,
                letterSpacing = 1.sp,
                color = TextPrimary
              )
              Text(
                text = "Honeywall & Deception Core (Kali Non-Root)",
                fontSize = 11.sp,
                color = CyberCyan
              )
            }
          }
        },
        actions = {
          Surface(
            shape = RoundedCornerShape(16.dp),
            color = GreenGlow,
            border = androidx.compose.foundation.BorderStroke(1.dp, CyberGreen),
            modifier = Modifier.padding(end = 12.dp)
          ) {
            Row(
              modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
              verticalAlignment = Alignment.CenterVertically,
              horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
              Box(
                modifier = Modifier
                  .size(8.dp)
                  .clip(CircleShape)
                  .background(CyberGreen)
              )
              Text("epoll ET", fontSize = 11.sp, color = CyberGreen, fontWeight = FontWeight.SemiBold)
            }
          }
        }
      )
    },
    bottomBar = {
      NavigationBar(
        containerColor = DarkSurface,
        contentColor = TextPrimary,
        tonalElevation = 8.dp,
        windowInsets = WindowInsets.navigationBars
      ) {
        tabs.forEachIndexed { index, (label, icon) ->
          val selected = selectedTab == index
          NavigationBarItem(
            modifier = Modifier.testTag("nav_tab_$index"),
            selected = selected,
            onClick = { selectedTab = index },
            icon = { Icon(icon, contentDescription = label) },
            label = { Text(label, fontSize = 11.sp) },
            colors = NavigationBarItemDefaults.colors(
              selectedIconColor = CyberGreen,
              selectedTextColor = CyberGreen,
              indicatorColor = GreenGlow,
              unselectedIconColor = TextMuted,
              unselectedTextColor = TextMuted
            )
          )
        }
      }
    }
  ) { paddingValues ->
    Box(
      modifier = Modifier
        .fillMaxSize()
        .padding(paddingValues)
    ) {
      when (selectedTab) {
        0 -> HoneywallTab(
          activeSessions = activeSessions,
          isolatedIps = isolatedIps,
          totalConnections = totalConnections,
          violations = rateLimitViolations,
          onIsolate = { session ->
            activeSessions.remove(session)
            isolatedIps.add(session.ip to "Aislamiento manual desde consola")
            rateLimitViolations++
            alerts.add(
              0,
              ForensicAlertUi(
                System.currentTimeMillis(),
                "Ahora",
                "critical",
                "Aislamiento Perimetral Manual",
                "Host ${session.ip} contenido. Syscall shutdown() ejecutada.",
                "Honeywall UI"
              )
            )
          },
          onUnblock = { ip ->
            val idx = isolatedIps.indexOfFirst { it.first == ip }
            if (idx >= 0) isolatedIps.removeAt(idx)
          }
        )
        1 -> AlertsTab(alerts = alerts)
        2 -> CliTerminalTab(
          logs = terminalLogs,
          activeSessions = activeSessions,
          isolatedIps = isolatedIps,
          onExecute = { cmd ->
            terminalLogs.add(TerminalLogUi("undahwoar@kali:~# $cmd", isCommand = true, color = CyberGreen))
            handleCliCommand(
              cmd,
              activeSessions,
              isolatedIps,
              totalConnections,
              rateLimitViolations,
              terminalLogs
            )
          }
        )
        3 -> LabModulesTab(
          onRunProbe = {
            totalConnections++
            val probeSession = ActiveSessionUi(19, "127.0.0.1", 54321, "00:00:00:00:00:00", 11, 2)
            activeSessions.add(probeSession)
            rateLimitViolations++
            isolatedIps.add("127.0.0.1" to "Exceso de tasa: 11 tramas/min (Máx 10)")
            alerts.add(
              0,
              ForensicAlertUi(
                System.currentTimeMillis(),
                "Ahora",
                "critical",
                "Alerta Honeywall: Pivoteo Detectado",
                "IP 127.0.0.1 mitigada automáticamente tras 11 peticiones en 60s.",
                "honeywall_probe.py"
              )
            )
          }
        )
      }
    }
  }
}

@Composable
fun HoneywallTab(
  activeSessions: List<ActiveSessionUi>,
  isolatedIps: List<Pair<String, String>>,
  totalConnections: Int,
  violations: Int,
  onIsolate: (ActiveSessionUi) -> Unit,
  onUnblock: (String) -> Unit
) {
  LazyColumn(
    modifier = Modifier
      .fillMaxSize()
      .padding(horizontal = 16.dp, vertical = 12.dp),
    verticalArrangement = Arrangement.spacedBy(16.dp)
  ) {
    // Tarjetas de Métricas de Epoll y Honeywall
    item {
      Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        MetricMiniCard("Activas epoll", "${activeSessions.size}", CyberGreen, Modifier.weight(1f))
        MetricMiniCard("Rate Violations", "$violations", AlertRed, Modifier.weight(1f))
        MetricMiniCard("Aisladas", "${isolatedIps.size}", WarningAmber, Modifier.weight(1f))
      }
    }

    // Banner de Política de Contención
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurfaceVariant),
        border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
      ) {
        Column(modifier = Modifier.padding(14.dp)) {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
          ) {
            Icon(Icons.Default.Speed, contentDescription = null, tint = WarningAmber, modifier = Modifier.size(18.dp))
            Text("Regla de Mitigación Undahwoar", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 13.sp)
          }
          Spacer(modifier = Modifier.height(6.dp))
          Text(
            "Umbral: 10 tramas salientes/minuto por descriptor de socket. Si se supera, se invoca shutdown(SHUT_RDWR), cierre del descriptor y contención de IP.",
            fontSize = 12.sp,
            color = TextSecondary,
            lineHeight = 16.sp
          )
        }
      }
    }

    // Lista de Sesiones Activas
    item {
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Text("Sesiones Activas en Puertos Altos", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 15.sp)
        Text("${activeSessions.size} conexiones", fontSize = 12.sp, color = CyberCyan)
      }
    }

    if (activeSessions.isEmpty()) {
      item {
        Card(
          modifier = Modifier.fillMaxWidth(),
          shape = RoundedCornerShape(10.dp),
          colors = CardDefaults.cardColors(containerColor = DarkSurface)
        ) {
          Box(modifier = Modifier.padding(24.dp).fillMaxWidth(), contentAlignment = Alignment.Center) {
            Text("No hay conexiones activas en este momento", color = TextMuted, fontSize = 13.sp)
          }
        }
      }
    } else {
      items(activeSessions) { session ->
        ActiveSessionCard(session = session, onIsolate = { onIsolate(session) })
      }
    }

    // Hosts Aislados (Lista Negra)
    item {
      Spacer(modifier = Modifier.height(8.dp))
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Text("Hosts en Contención Perimetral", fontWeight = FontWeight.Bold, color = AlertRed, fontSize = 15.sp)
        Text("${isolatedIps.size} aisladas", fontSize = 12.sp, color = AlertRed)
      }
    }

    if (isolatedIps.isEmpty()) {
      item {
        Text("Ningún host aislado actualmente.", fontSize = 12.sp, color = TextMuted)
      }
    } else {
      items(isolatedIps) { (ip, reason) ->
        IsolatedHostCard(ip = ip, reason = reason, onUnblock = { onUnblock(ip) })
      }
    }
  }
}

@Composable
fun MetricMiniCard(title: String, value: String, color: Color, modifier: Modifier = Modifier) {
  Card(
    modifier = modifier,
    shape = RoundedCornerShape(10.dp),
    colors = CardDefaults.cardColors(containerColor = DarkSurface),
    border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
  ) {
    Column(modifier = Modifier.padding(12.dp)) {
      Text(title, fontSize = 11.sp, color = TextSecondary, maxLines = 1)
      Spacer(modifier = Modifier.height(4.dp))
      Text(value, fontSize = 20.sp, fontWeight = FontWeight.Bold, color = color)
    }
  }
}

@Composable
fun ActiveSessionCard(session: ActiveSessionUi, onIsolate: () -> Unit) {
  val ratePct = (session.outboundRate.toFloat() / 10f).coerceIn(0f, 1f)
  val rateColor by animateColorAsState(
    targetValue = if (session.outboundRate >= 9) AlertRed else if (session.outboundRate >= 6) WarningAmber else CyberGreen,
    label = "rateColor"
  )

  Card(
    modifier = Modifier.fillMaxWidth(),
    shape = RoundedCornerShape(10.dp),
    colors = CardDefaults.cardColors(containerColor = DarkSurface),
    border = androidx.compose.foundation.BorderStroke(1.dp, if (session.outboundRate >= 9) RedGlow else DarkBorder)
  ) {
    Column(modifier = Modifier.padding(14.dp)) {
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          Text("FD ${session.fd}", fontWeight = FontWeight.Bold, color = CyberCyan, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
          Text(session.ip, fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 14.sp)
          Text(":${session.port}", color = TextSecondary, fontSize = 12.sp)
        }
        OutlinedButton(
          onClick = onIsolate,
          modifier = Modifier.height(30.dp).testTag("btn_isolate_${session.fd}"),
          contentPadding = PaddingValues(horizontal = 10.dp, vertical = 0.dp),
          colors = ButtonDefaults.outlinedButtonColors(contentColor = AlertRed),
          border = androidx.compose.foundation.BorderStroke(1.dp, AlertRed)
        ) {
          Text("Aislar", fontSize = 11.sp, fontWeight = FontWeight.Bold)
        }
      }

      Spacer(modifier = Modifier.height(8.dp))
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
      ) {
        Text("MAC: ${session.mac}", fontSize = 11.sp, color = TextMuted, fontFamily = FontFamily.Monospace)
        Text("Activo: ${session.connectedAgoSec}s", fontSize = 11.sp, color = TextMuted)
      }

      Spacer(modifier = Modifier.height(8.dp))
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Text("Tasa Saliente:", fontSize = 11.sp, color = TextSecondary)
        Text("${session.outboundRate}/10 req/min", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = rateColor)
      }
      Spacer(modifier = Modifier.height(4.dp))
      LinearProgressIndicator(
        progress = { ratePct },
        modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp)),
        color = rateColor,
        trackColor = DarkSurfaceVariant
      )
    }
  }
}

@Composable
fun IsolatedHostCard(ip: String, reason: String, onUnblock: () -> Unit) {
  Card(
    modifier = Modifier.fillMaxWidth(),
    shape = RoundedCornerShape(10.dp),
    colors = CardDefaults.cardColors(containerColor = DarkSurface),
    border = androidx.compose.foundation.BorderStroke(1.dp, RedGlow)
  ) {
    Row(
      modifier = Modifier.padding(12.dp).fillMaxWidth(),
      horizontalArrangement = Arrangement.SpaceBetween,
      verticalAlignment = Alignment.CenterVertically
    ) {
      Column(modifier = Modifier.weight(1f)) {
        Text(ip, fontWeight = FontWeight.Bold, color = AlertRed, fontSize = 13.sp)
        Text(reason, fontSize = 11.sp, color = TextSecondary, lineHeight = 14.sp)
      }
      TextButton(
        onClick = onUnblock,
        modifier = Modifier.testTag("btn_unblock_$ip")
      ) {
        Text("Desbloquear", color = CyberCyan, fontSize = 12.sp)
      }
    }
  }
}

@Composable
fun AlertsTab(alerts: List<ForensicAlertUi>) {
  LazyColumn(
    modifier = Modifier.fillMaxSize().padding(16.dp),
    verticalArrangement = Arrangement.spacedBy(12.dp)
  ) {
    item {
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Column {
          Text("Eventos Forenses (inotify)", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 16.sp)
          Text("Suscripción IN_MODIFY en logs y despacho a notify-send", fontSize = 11.sp, color = TextSecondary)
        }
        Icon(Icons.Default.GraphicEq, contentDescription = null, tint = CyberGreen)
      }
    }

    items(alerts, key = { it.id }) { alert ->
      val (borderColor, icon, tagColor) = when (alert.severity) {
        "critical" -> Triple(AlertRed, Icons.Default.Warning, AlertRed)
        "warning" -> Triple(WarningAmber, Icons.Default.ErrorOutline, WarningAmber)
        else -> Triple(CyberCyan, Icons.Default.Info, CyberCyan)
      }

      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, borderColor.copy(alpha = 0.5f))
      ) {
        Column(modifier = Modifier.padding(14.dp)) {
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
              Icon(icon, contentDescription = null, tint = tagColor, modifier = Modifier.size(16.dp))
              Text(alert.title, fontWeight = FontWeight.Bold, color = tagColor, fontSize = 13.sp)
            }
            Text(alert.time, fontSize = 11.sp, color = TextMuted)
          }
          Spacer(modifier = Modifier.height(6.dp))
          Text(alert.message, fontSize = 12.sp, color = TextPrimary, lineHeight = 16.sp)
          Spacer(modifier = Modifier.height(6.dp))
          Text("Origen: ${alert.source}", fontSize = 10.sp, color = TextMuted, fontFamily = FontFamily.Monospace)
        }
      }
    }
  }
}

@Composable
fun CliTerminalTab(
  logs: List<TerminalLogUi>,
  activeSessions: List<ActiveSessionUi>,
  isolatedIps: List<Pair<String, String>>,
  onExecute: (String) -> Unit
) {
  var inputCommand by remember { mutableStateOf("") }
  val listState = rememberLazyListState()
  val coroutineScope = rememberCoroutineScope()

  // Sugerencias dinámicas de tres niveles del completer
  val suggestions = remember(inputCommand, activeSessions, isolatedIps) {
    val trimmed = inputCommand.trim()
    when {
      trimmed.startsWith("isolate ") -> activeSessions.map { "isolate ${it.ip}" }
      trimmed.startsWith("unblock ") -> isolatedIps.map { "unblock ${it.first}" }
      trimmed.startsWith("audit ") -> listOf("audit /proc/net/tcp", "audit /proc/net/arp", "audit nmcli", "audit ports")
      trimmed.startsWith("run-module ") -> listOf("run-module test_port_scan.py", "run-module brute_force_sim.py", "run-module honeywall_probe.py")
      else -> listOf("status", "honeywall-stats", "connections", "isolate", "unblock", "audit /proc/net/tcp", "run-module honeywall_probe.py", "logs", "clear", "help")
    }
  }

  LaunchedEffect(logs.size) {
    if (logs.isNotEmpty()) {
      coroutineScope.launch {
        listState.animateScrollToItem(logs.size - 1)
      }
    }
  }

  Column(modifier = Modifier.fillMaxSize().padding(12.dp)) {
    // Ventana de Terminal
    Box(
      modifier = Modifier
        .weight(1f)
        .fillMaxWidth()
        .clip(RoundedCornerShape(10.dp))
        .background(Color(0xFF06090F))
        .border(1.dp, DarkBorder, RoundedCornerShape(10.dp))
        .padding(12.dp)
    ) {
      LazyColumn(state = listState, modifier = Modifier.fillMaxSize()) {
        items(logs) { log ->
          Text(
            text = log.text,
            color = log.color,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.padding(vertical = 2.dp)
          )
        }
      }
    }

    Spacer(modifier = Modifier.height(8.dp))

    // Barra de autocompletado predictivo dinámico (Niveles 1, 2 y 3)
    LazyRow(
      modifier = Modifier.fillMaxWidth(),
      horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
      items(suggestions) { sugg ->
        SuggestionChip(
          onClick = { inputCommand = sugg },
          label = { Text(sugg, fontSize = 11.sp, color = CyberCyan) },
          colors = SuggestionChipDefaults.suggestionChipColors(containerColor = DarkSurface),
          border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
        )
      }
    }

    Spacer(modifier = Modifier.height(6.dp))

    // Caja de entrada de comando
    Row(
      modifier = Modifier.fillMaxWidth(),
      verticalAlignment = Alignment.CenterVertically,
      horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
      OutlinedTextField(
        value = inputCommand,
        onValueChange = { inputCommand = it },
        modifier = Modifier.weight(1f).testTag("cli_input_field"),
        placeholder = { Text("Escribe comando...", fontSize = 12.sp, color = TextMuted) },
        singleLine = true,
        textStyle = androidx.compose.ui.text.TextStyle(
          color = CyberGreen,
          fontSize = 13.sp,
          fontFamily = FontFamily.Monospace
        ),
        colors = OutlinedTextFieldDefaults.colors(
          focusedContainerColor = DarkSurface,
          unfocusedContainerColor = DarkSurface,
          focusedBorderColor = CyberGreen,
          unfocusedBorderColor = DarkBorder
        ),
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
        keyboardActions = KeyboardActions(onSend = {
          if (inputCommand.isNotBlank()) {
            onExecute(inputCommand)
            inputCommand = ""
          }
        })
      )

      IconButton(
        onClick = {
          if (inputCommand.isNotBlank()) {
            onExecute(inputCommand)
            inputCommand = ""
          }
        },
        modifier = Modifier
          .size(48.dp)
          .clip(RoundedCornerShape(8.dp))
          .background(GreenGlow)
          .border(1.dp, CyberGreen, RoundedCornerShape(8.dp))
          .testTag("cli_send_button")
      ) {
        Icon(Icons.Default.Send, contentDescription = "Enviar", tint = CyberGreen)
      }
    }
  }
}

fun handleCliCommand(
  cmd: String,
  sessions: MutableList<ActiveSessionUi>,
  isolated: MutableList<Pair<String, String>>,
  total: Int,
  violations: Int,
  terminalLogs: MutableList<TerminalLogUi>
) {
  val parts = cmd.trim().split("\\s+".toRegex())
  val base = parts.firstOrNull()?.lowercase() ?: ""
  val arg = if (parts.size > 1) parts[1] else ""

  when (base) {
    "help" -> {
      terminalLogs.add(TerminalLogUi("Comandos disponibles:\n  status            - Estado del motor epoll y Honeywall\n  honeywall-stats   - Umbrales de contención activa\n  connections       - Lista sesiones activas con IP/MAC\n  isolate <ip>      - Aísla perimetralmente un host\n  unblock <ip>      - Remueve IP de la lista negra\n  audit <target>    - /proc/net/tcp o /proc/net/arp\n  run-module <mod>  - Ejecuta módulos de capacitación\n  clear             - Limpia la pantalla", color = TextSecondary))
    }
    "status" -> {
      terminalLogs.add(TerminalLogUi("• Motor: select.epoll (Edge-Triggered, non-blocking)\n• Puertos en escucha: 2222 (SSH), 8080 (HTTP), 8443 (HTTPS)\n• Sesiones activas: ${sessions.size}\n• Total capturadas: $total\n• Violaciones rate-limit: $violations", color = CyberCyan))
    }
    "honeywall-stats" -> {
      terminalLogs.add(TerminalLogUi("• Umbral máximo: 10 tramas/min\n• Acción: shutdown(SHUT_RDWR) + close() inmediato\n• Hosts aislados actualmente: ${isolated.size}", color = WarningAmber))
    }
    "connections" -> {
      if (sessions.isEmpty()) {
        terminalLogs.add(TerminalLogUi("No hay conexiones activas registradas.", color = TextMuted))
      } else {
        val s = buildString {
          append("FD   IP               PUERTO  MAC                TASA\n")
          sessions.forEach {
            append("${it.fd.toString().padEnd(4)} ${it.ip.padEnd(16)} ${it.port.toString().padEnd(7)} ${it.mac.padEnd(18)} ${it.outboundRate}/10\n")
          }
        }
        terminalLogs.add(TerminalLogUi(s, color = TextPrimary))
      }
    }
    "isolate" -> {
      if (arg.isBlank()) {
        terminalLogs.add(TerminalLogUi("Uso: isolate <IP_ADDRESS>", color = AlertRed))
      } else {
        val found = sessions.find { it.ip == arg }
        if (found != null) sessions.remove(found)
        isolated.add(arg to "Aislamiento manual vía CLI")
        terminalLogs.add(TerminalLogUi("[+] IP $arg aislada perimetralmente. Descriptores cerrados.", color = CyberGreen))
      }
    }
    "unblock" -> {
      if (arg.isBlank()) {
        terminalLogs.add(TerminalLogUi("Uso: unblock <IP_ADDRESS>", color = AlertRed))
      } else {
        val idx = isolated.indexOfFirst { it.first == arg }
        if (idx >= 0) {
          isolated.removeAt(idx)
          terminalLogs.add(TerminalLogUi("[+] IP $arg desbloqueada.", color = CyberGreen))
        } else {
          terminalLogs.add(TerminalLogUi("[*] La IP $arg no está en lista de aislamiento.", color = WarningAmber))
        }
      }
    }
    "audit" -> {
      if (arg.contains("tcp")) {
        terminalLogs.add(TerminalLogUi("Parsing /proc/net/tcp (Kernel Space Sockets):\n [LISTEN] 0.0.0.0:2222 -> Inode 41209 (Honeypot SSH)\n [LISTEN] 0.0.0.0:8080 -> Inode 41210 (Honeypot HTTP)\n [ESTABLISHED] 127.0.0.1:8888 -> Inode 41299 (Web API)", color = CyberCyan))
      } else if (arg.contains("arp")) {
        terminalLogs.add(TerminalLogUi("Parsing /proc/net/arp:\n 192.168.1.105 -> 08:00:27:fa:31:0a (eth0)\n 10.0.2.15     -> 52:54:00:12:34:56 (eth0)", color = CyberCyan))
      } else {
        terminalLogs.add(TerminalLogUi("Objetivo desconocido. Opciones: /proc/net/tcp, /proc/net/arp", color = WarningAmber))
      }
    }
    "clear" -> {
      terminalLogs.clear()
    }
    else -> {
      terminalLogs.add(TerminalLogUi("Comando no reconocido: '$base'. Escriba 'help'.", color = AlertRed))
    }
  }
}

@Composable
fun LabModulesTab(onRunProbe: () -> Unit) {
  var probeTriggered by remember { mutableStateOf(false) }

  LazyColumn(
    modifier = Modifier.fillMaxSize().padding(16.dp),
    verticalArrangement = Arrangement.spacedBy(16.dp)
  ) {
    item {
      Text("Módulos de Capacitación y Pruebas", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 16.sp)
      Text("Scripts interactivos en ./modules/ para validar la contención perimetral", fontSize = 12.sp, color = TextSecondary)
    }

    // Módulo 1: Honeywall Probe (Trigger de contención)
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, CyberGreen)
      ) {
        Column(modifier = Modifier.padding(14.dp)) {
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Text("honeywall_probe.py", fontWeight = FontWeight.Bold, color = CyberGreen, fontSize = 14.sp)
            Surface(shape = RoundedCornerShape(4.dp), color = GreenGlow) {
              Text("Rate Limit Test", fontSize = 10.sp, color = CyberGreen, modifier = Modifier.padding(4.dp))
            }
          }
          Spacer(modifier = Modifier.height(6.dp))
          Text(
            "Emite intencionalmente 12 peticiones interactivas en menos de 60 segundos hacia el puerto simulado 2222 para comprobar el corte forzado por shutdown(SHUT_RDWR).",
            fontSize = 12.sp,
            color = TextSecondary
          )
          Spacer(modifier = Modifier.height(10.dp))
          Button(
            onClick = {
              probeTriggered = true
              onRunProbe()
            },
            colors = ButtonDefaults.buttonColors(containerColor = CyberGreen, contentColor = Color.Black),
            modifier = Modifier.testTag("btn_run_probe")
          ) {
            Icon(Icons.Default.PlayArrow, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("Ejecutar Prueba de Pivoteo", fontWeight = FontWeight.Bold, fontSize = 12.sp)
          }
        }
      }
    }

    // Módulo 2: Port Scan Test
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
      ) {
        Column(modifier = Modifier.padding(14.dp)) {
          Text("test_port_scan.py", fontWeight = FontWeight.Bold, color = CyberCyan, fontSize = 14.sp)
          Spacer(modifier = Modifier.height(6.dp))
          Text(
            "Sondeo asíncrono TCP Connect contra los puertos 2222, 8080, 8443 y 33060 capturados por epoll.",
            fontSize = 12.sp,
            color = TextSecondary
          )
        }
      }
    }

    // Módulo 3: Brute Force SSH Sim
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
      ) {
        Column(modifier = Modifier.padding(14.dp)) {
          Text("brute_force_sim.py", fontWeight = FontWeight.Bold, color = WarningAmber, fontSize = 14.sp)
          Spacer(modifier = Modifier.height(6.dp))
          Text(
            "Simula intentos repetidos de autenticación SSH para activar las reglas regex de inotify y despachar alertas notify-send.",
            fontSize = 12.sp,
            color = TextSecondary
          )
        }
      }
    }

    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurfaceVariant)
      ) {
        Column(modifier = Modifier.padding(14.dp)) {
          Text("Servidor Web & API Integrado", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 13.sp)
          Spacer(modifier = Modifier.height(4.dp))
          Text("Dashboard accesible en: http://127.0.0.1:8888\nEndpoints REST: /api/status, /api/connections, /api/alerts, /api/isolate", fontSize = 11.sp, color = CyberCyan, fontFamily = FontFamily.Monospace)
        }
      }
    }
  }
}
