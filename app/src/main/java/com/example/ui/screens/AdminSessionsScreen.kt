package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.local.entity.MonitoredSessionEntity
import com.example.ui.theme.*

@Composable
fun AdminSessionsScreen(
  sessions: List<MonitoredSessionEntity>,
  isOnline: Boolean,
  onIsolateConfirmed: (MonitoredSessionEntity) -> Unit,
  onUnblockConfirmed: (MonitoredSessionEntity) -> Unit,
  onObserveConfirmed: (MonitoredSessionEntity, String) -> Unit,
  onRefreshFromDaemon: () -> Unit
) {
  var pendingIsolateSession by remember { mutableStateOf<MonitoredSessionEntity?>(null) }
  var pendingObserveSession by remember { mutableStateOf<MonitoredSessionEntity?>(null) }
  var observeReasonInput by remember { mutableStateOf("Actividad inusual observada por operador") }
  var selectedSessionFilter by remember { mutableStateOf("All") }
  var sessionSearchQuery by remember { mutableStateOf("") }

  val filteredSessions = remember(sessions, selectedSessionFilter, sessionSearchQuery) {
    sessions.filter { s ->
      val isIsolated = s.currentStatus == "isolated" || s.isMacBlocked
      val isObserved = s.currentStatus == "en_observacion" || s.isInObservation
      val matchesFilter = when (selectedSessionFilter) {
        "isolated" -> isIsolated
        "en_observacion" -> isObserved
        "active" -> !isIsolated && !isObserved
        else -> true
      }
      val matchesQuery = if (sessionSearchQuery.isBlank()) true else {
        s.ipAddress.contains(sessionSearchQuery, ignoreCase = true) ||
          s.macAddress.contains(sessionSearchQuery, ignoreCase = true) ||
          s.deviceId.contains(sessionSearchQuery, ignoreCase = true) ||
          s.service.contains(sessionSearchQuery, ignoreCase = true) ||
          s.visitorLabel.contains(sessionSearchQuery, ignoreCase = true)
      }
      matchesFilter && matchesQuery
    }
  }

  Column(
    modifier = Modifier
      .fillMaxSize()
      .padding(horizontal = 14.dp, vertical = 8.dp)
  ) {
    Card(
      modifier = Modifier.fillMaxWidth(),
      shape = RoundedCornerShape(10.dp),
      colors = CardDefaults.cardColors(containerColor = DarkSurface),
      border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
    ) {
      Row(
        modifier = Modifier.padding(12.dp).fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Column(modifier = Modifier.weight(1f)) {
          Text("Sesiones Unificadas (/api/sessions)", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 12.sp)
          Text("Origen, destino y estado desde SQLite del daemon. Acciones de aislamiento con confirmación.", fontSize = 10.sp, color = TextSecondary)
        }
        Icon(Icons.Default.AdminPanelSettings, contentDescription = null, tint = WarningAmber, modifier = Modifier.size(20.dp))
      }
    }

    Spacer(modifier = Modifier.height(8.dp))

    Row(
      modifier = Modifier.fillMaxWidth(),
      horizontalArrangement = Arrangement.spacedBy(8.dp),
      verticalAlignment = Alignment.CenterVertically
    ) {
      OutlinedTextField(
        value = sessionSearchQuery,
        onValueChange = { sessionSearchQuery = it },
        modifier = Modifier
          .weight(1f)
          .testTag("search_admin_sessions"),
        placeholder = { Text("Buscar por IP, MAC, device_id o servicio...", fontSize = 11.sp, color = TextMuted) },
        leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(18.dp)) },
        trailingIcon = {
          if (sessionSearchQuery.isNotEmpty()) {
            IconButton(onClick = { sessionSearchQuery = "" }) {
              Icon(Icons.Default.Close, contentDescription = null, tint = TextSecondary, modifier = Modifier.size(16.dp))
            }
          }
        },
        singleLine = true,
        textStyle = androidx.compose.ui.text.TextStyle(fontSize = 12.sp, color = TextPrimary),
        shape = RoundedCornerShape(8.dp),
        colors = OutlinedTextFieldDefaults.colors(
          focusedContainerColor = DarkSurface,
          unfocusedContainerColor = DarkSurface,
          focusedBorderColor = CyberCyan,
          unfocusedBorderColor = DarkBorder
        )
      )

      IconButton(
        onClick = onRefreshFromDaemon,
        modifier = Modifier
          .size(48.dp)
          .clip(RoundedCornerShape(8.dp))
          .background(DarkSurface)
          .testTag("refresh_sessions_button")
      ) {
        Icon(Icons.Default.Refresh, contentDescription = "Actualizar sesiones del daemon", tint = CyberCyan)
      }
    }

    Spacer(modifier = Modifier.height(6.dp))

    val isolatedCount = sessions.count { it.currentStatus == "isolated" || it.isMacBlocked }
    val observedCount = sessions.count { it.currentStatus == "en_observacion" || it.isInObservation }
    val otherCount = sessions.size - isolatedCount - observedCount

    LazyRow(
      modifier = Modifier.fillMaxWidth(),
      horizontalArrangement = Arrangement.spacedBy(6.dp),
      verticalAlignment = Alignment.CenterVertically
    ) {
      val options = listOf(
        "All" to "Todas (${sessions.size})",
        "isolated" to "Aisladas ($isolatedCount)",
        "en_observacion" to "En Observación ($observedCount)",
        "active" to "Activas/Cerradas ($otherCount)"
      )
      items(options) { (key, label) ->
        val isSelected = selectedSessionFilter == key
        val (chipBg, chipBorder, chipText) = when (key) {
          "isolated" -> Triple(if (isSelected) RedGlow else DarkSurface, AlertRed, AlertRed)
          "en_observacion" -> Triple(if (isSelected) AmberGlow else DarkSurface, WarningAmber, WarningAmber)
          "active" -> Triple(if (isSelected) GreenGlow else DarkSurface, CyberGreen, CyberGreen)
          else -> Triple(if (isSelected) CyanGlow else DarkSurface, CyberCyan, CyberCyan)
        }

        FilterChip(
          selected = isSelected,
          onClick = { selectedSessionFilter = key },
          label = { Text(label, fontSize = 10.sp, fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal) },
          colors = FilterChipDefaults.filterChipColors(
            containerColor = DarkSurface,
            labelColor = TextSecondary,
            selectedContainerColor = chipBg,
            selectedLabelColor = chipText
          ),
          border = FilterChipDefaults.filterChipBorder(
            borderColor = if (isSelected) chipBorder else DarkBorder,
            selectedBorderColor = chipBorder,
            borderWidth = if (isSelected) 1.5.dp else 1.dp,
            enabled = true,
            selected = isSelected
          )
        )
      }
    }

    Spacer(modifier = Modifier.height(8.dp))

    if (filteredSessions.isEmpty()) {
      Box(modifier = Modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
          Icon(
            imageVector = if (isOnline) Icons.Default.Dns else Icons.Default.CloudOff,
            contentDescription = null,
            tint = TextMuted,
            modifier = Modifier.size(36.dp)
          )
          Spacer(modifier = Modifier.height(8.dp))
          Text(
            text = if (isOnline) "No hay sesiones registradas en el daemon." else "Sin conexión — caché de sesiones vacía.",
            color = TextMuted,
            fontSize = 11.sp
          )
        }
      }
    } else {
      LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        contentPadding = PaddingValues(bottom = 24.dp)
      ) {
        items(filteredSessions, key = { it.id }) { session ->
          SessionItemCard(
            session = session,
            onPromptIsolate = { pendingIsolateSession = session },
            onUnblock = { onUnblockConfirmed(session) },
            onPromptObserve = {
              observeReasonInput = "Marcada en observación desde panel Android"
              pendingObserveSession = session
            }
          )
        }
      }
    }
  }

  pendingIsolateSession?.let { target ->
    AlertDialog(
      onDismissRequest = { pendingIsolateSession = null },
      containerColor = DarkSurface,
      titleContentColor = AlertRed,
      textContentColor = TextSecondary,
      icon = { Icon(Icons.Default.WarningAmber, contentDescription = null, tint = AlertRed) },
      title = { Text("Confirmación Requerida (Invariante 5)", fontSize = 13.sp, fontWeight = FontWeight.Bold) },
      text = {
        Text(
          "¿Confirmas el aislamiento de la IP ${target.ipAddress} (sesión #${target.daemonSessionId ?: target.id}, device_id: ${target.deviceId}) mediante POST /api/isolate?",
          fontSize = 11.sp,
          color = TextPrimary,
          lineHeight = 15.sp
        )
      },
      confirmButton = {
        Button(
          onClick = {
            onIsolateConfirmed(target)
            pendingIsolateSession = null
          },
          colors = ButtonDefaults.buttonColors(containerColor = AlertRed, contentColor = Color.White)
        ) {
          Text("Confirmar Aislamiento", fontSize = 11.sp, fontWeight = FontWeight.Bold)
        }
      },
      dismissButton = {
        TextButton(onClick = { pendingIsolateSession = null }) {
          Text("Cancelar", color = TextSecondary, fontSize = 11.sp)
        }
      }
    )
  }

  pendingObserveSession?.let { target ->
    AlertDialog(
      onDismissRequest = { pendingObserveSession = null },
      containerColor = DarkSurface,
      titleContentColor = WarningAmber,
      textContentColor = TextSecondary,
      title = { Text("Marcar Sesión en Observación", fontSize = 13.sp, fontWeight = FontWeight.Bold) },
      text = {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Text(
            "Se enviará POST /api/sessions/${target.daemonSessionId ?: target.id}/observe para ${target.ipAddress}.",
            fontSize = 11.sp,
            color = TextPrimary
          )
          OutlinedTextField(
            value = observeReasonInput,
            onValueChange = { observeReasonInput = it },
            label = { Text("Motivo (reason)", fontSize = 10.sp) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag("observe_reason_input"),
            textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp, color = TextPrimary)
          )
        }
      },
      confirmButton = {
        Button(
          onClick = {
            onObserveConfirmed(target, observeReasonInput.ifBlank { "Marcada en observación por operador" })
            pendingObserveSession = null
          },
          colors = ButtonDefaults.buttonColors(containerColor = WarningAmber, contentColor = Color.Black)
        ) {
          Text("Marcar en observación", fontSize = 11.sp, fontWeight = FontWeight.Bold)
        }
      },
      dismissButton = {
        TextButton(onClick = { pendingObserveSession = null }) {
          Text("Cancelar", color = TextSecondary, fontSize = 11.sp)
        }
      }
    )
  }
}

@Composable
fun SessionItemCard(
  session: MonitoredSessionEntity,
  onPromptIsolate: () -> Unit,
  onUnblock: () -> Unit,
  onPromptObserve: () -> Unit
) {
  var isExpanded by remember { mutableStateOf(false) }
  val isIsolated = session.currentStatus == "isolated" || session.isMacBlocked
  val isObserved = session.currentStatus == "en_observacion" || session.isInObservation

  val (borderColor, statusBadgeBg, statusBadgeColor, statusLabel) = when {
    isIsolated -> Quadruple(AlertRed, RedGlow, AlertRed, "ISOLATED")
    isObserved -> Quadruple(WarningAmber, AmberGlow, WarningAmber, "EN OBSERVACIÓN")
    session.currentStatus == "closed" -> Quadruple(CyberCyan, CyanGlow, CyberCyan, "CLOSED")
    else -> Quadruple(CyberGreen, GreenGlow, CyberGreen, session.currentStatus.uppercase().ifBlank { "ACTIVE" })
  }

  Card(
    modifier = Modifier
      .fillMaxWidth()
      .testTag("session_card_${session.daemonSessionId ?: session.id}"),
    shape = RoundedCornerShape(10.dp),
    colors = CardDefaults.cardColors(containerColor = DarkSurface),
    border = androidx.compose.foundation.BorderStroke(1.dp, borderColor.copy(alpha = 0.4f))
  ) {
    Column(modifier = Modifier.padding(12.dp)) {
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
          Surface(shape = RoundedCornerShape(4.dp), color = statusBadgeBg) {
            Text(
              text = statusLabel,
              color = statusBadgeColor,
              fontSize = 9.sp,
              fontWeight = FontWeight.Bold,
              modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
            )
          }
          Text(
            text = "#${session.daemonSessionId ?: session.id} ${session.ipAddress}",
            fontWeight = FontWeight.Bold,
            color = TextPrimary,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace
          )
        }

        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
          if (!isObserved && !isIsolated && (session.daemonSessionId != null || session.isDemo)) {
            OutlinedButton(
              onClick = onPromptObserve,
              modifier = Modifier.height(26.dp),
              contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
              colors = ButtonDefaults.outlinedButtonColors(contentColor = WarningAmber),
              border = androidx.compose.foundation.BorderStroke(1.dp, WarningAmber.copy(alpha = 0.7f))
            ) {
              Text("Observar", fontSize = 9.sp, fontWeight = FontWeight.Bold)
            }
          }

          if (isIsolated) {
            OutlinedButton(
              onClick = onUnblock,
              modifier = Modifier.height(26.dp),
              contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
              colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberCyan),
              border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan.copy(alpha = 0.6f))
            ) {
              Text("Desbloquear", fontSize = 9.sp, fontWeight = FontWeight.Bold)
            }
          } else {
            Button(
              onClick = onPromptIsolate,
              modifier = Modifier.height(26.dp),
              contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
              colors = ButtonDefaults.buttonColors(containerColor = AlertRed, contentColor = Color.White)
            ) {
              Text("Aislar", fontSize = 9.sp, fontWeight = FontWeight.Bold)
            }
          }

          IconButton(
            onClick = { isExpanded = !isExpanded },
            modifier = Modifier.size(26.dp)
          ) {
            Icon(
              imageVector = if (isExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
              contentDescription = "Detalles",
              tint = TextSecondary,
              modifier = Modifier.size(16.dp)
            )
          }
        }
      }

      Spacer(modifier = Modifier.height(6.dp))
      Text("device_id: ${session.deviceId.ifBlank { "—" }}", fontSize = 10.sp, color = CyberCyan, fontFamily = FontFamily.Monospace)
      Text(
        "MAC: ${session.macAddress.ifBlank { "—" }} | Servicio: ${session.service.ifBlank { "—" }}:${session.destPort}",
        fontSize = 10.sp,
        color = TextMuted,
        fontFamily = FontFamily.Monospace
      )

      if (session.visitorLabel.isNotBlank()) {
        Spacer(modifier = Modifier.height(2.dp))
        Text("visitor_label: ${session.visitorLabel}", fontSize = 10.sp, color = TextPrimary)
      }

      if (session.observedReason.isNotBlank()) {
        Text("observed_reason: ${session.observedReason}", fontSize = 9.sp, color = WarningAmber, fontWeight = FontWeight.SemiBold)
      }

      AnimatedVisibility(visible = isExpanded) {
        Column(modifier = Modifier.padding(top = 8.dp)) {
          Divider(color = DarkBorder, modifier = Modifier.padding(vertical = 4.dp))
          Text("Detalle real (/api/sessions):", fontSize = 10.sp, color = CyberCyan, fontWeight = FontWeight.Bold)
          Text("• mode: ${session.mode} | device_type: ${session.deviceType.ifBlank { "—" }}", fontSize = 9.sp, color = TextSecondary, fontFamily = FontFamily.Monospace)
          Text("• duration_sec: ${session.durationSeconds}s | bytes_in: ${session.bytesIn} | bytes_out: ${session.bytesOut}", fontSize = 9.sp, color = TextSecondary, fontFamily = FontFamily.Monospace)
          if (session.browserFingerprint.isNotBlank()) {
            Text("• fingerprints.browser: ${session.browserFingerprint}", fontSize = 9.sp, color = TextSecondary, fontFamily = FontFamily.Monospace)
          }
          if (session.networkFingerprint.isNotBlank()) {
            Text("• fingerprints.network: ${session.networkFingerprint}", fontSize = 9.sp, color = TextSecondary, fontFamily = FontFamily.Monospace)
          }
          if (session.dhcpFingerprint.isNotBlank()) {
            Text("• fingerprints.dhcp: ${session.dhcpFingerprint}", fontSize = 9.sp, color = TextSecondary, fontFamily = FontFamily.Monospace)
          }
          session.honeytokenTouched?.let {
            Text("• honeytoken_touched: $it", fontSize = 9.sp, color = AlertRed, fontFamily = FontFamily.Monospace)
          }
        }
      }
    }
  }
}

data class Quadruple<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)
