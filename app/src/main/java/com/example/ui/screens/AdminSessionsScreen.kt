package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
  onBlockMacConfirmed: (String, String) -> Unit,
  onUnblockMacConfirmed: (String, String) -> Unit
) {
  var pendingBlockTarget by remember { mutableStateOf<Pair<String, String>?>(null) } // mac to deviceId
  var selectedSessionFilter by remember { mutableStateOf("All") }
  var sessionSearchQuery by remember { mutableStateOf("") }

  val filteredSessions = remember(sessions, selectedSessionFilter, sessionSearchQuery) {
    sessions.filter { s ->
      val matchesFilter = when (selectedSessionFilter) {
        "Blocked" -> s.isMacBlocked || s.currentStatus == "Blocked"
        "Alerted" -> s.isInObservation || s.currentStatus == "Alerted"
        "Normal" -> !s.isMacBlocked && !s.isInObservation && s.currentStatus == "Normal"
        else -> true
      }
      val matchesQuery = if (sessionSearchQuery.isBlank()) true else {
        s.ipAddress.contains(sessionSearchQuery, ignoreCase = true) ||
        s.macAddress.contains(sessionSearchQuery, ignoreCase = true) ||
        s.deviceId.contains(sessionSearchQuery, ignoreCase = true) ||
        s.emailsUsedCsv.contains(sessionSearchQuery, ignoreCase = true) ||
        s.detectedAnomaliesCsv.contains(sessionSearchQuery, ignoreCase = true)
      }
      matchesFilter && matchesQuery
    }
  }

  Column(
    modifier = Modifier
      .fillMaxSize()
      .padding(horizontal = 14.dp, vertical = 8.dp)
  ) {
    // Cabecera Informativa
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
          Text("Panel de Administración y Correlación (Invariante 1)", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 12.sp)
          Text("Identificación por device_id compuesto (anti MAC spoofing/NAT). Bloqueo sujeto a confirmación.", fontSize = 10.sp, color = TextSecondary)
        }
        Icon(Icons.Default.AdminPanelSettings, contentDescription = null, tint = WarningAmber, modifier = Modifier.size(20.dp))
      }
    }

    Spacer(modifier = Modifier.height(8.dp))

    // Buscador
    OutlinedTextField(
      value = sessionSearchQuery,
      onValueChange = { sessionSearchQuery = it },
      modifier = Modifier
        .fillMaxWidth()
        .testTag("search_admin_sessions"),
      placeholder = { Text("Buscar por IP, MAC, device_id o email...", fontSize = 11.sp, color = TextMuted) },
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

    Spacer(modifier = Modifier.height(6.dp))

    // Filtros por Estado
    val blockedCount = sessions.count { it.isMacBlocked || it.currentStatus == "Blocked" }
    val alertedCount = sessions.count { it.isInObservation || it.currentStatus == "Alerted" }
    val normalCount = sessions.count { !it.isMacBlocked && !it.isInObservation && it.currentStatus == "Normal" }

    LazyRow(
      modifier = Modifier.fillMaxWidth(),
      horizontalArrangement = Arrangement.spacedBy(6.dp),
      verticalAlignment = Alignment.CenterVertically
    ) {
      val options = listOf(
        "All" to "Todas (${sessions.size})",
        "Blocked" to "Bloqueadas ($blockedCount)",
        "Alerted" to "En Observación ($alertedCount)",
        "Normal" to "Nominales ($normalCount)"
      )
      items(options) { (key, label) ->
        val isSelected = selectedSessionFilter == key
        val (chipBg, chipBorder, chipText) = when (key) {
          "Blocked" -> Triple(if (isSelected) RedGlow else DarkSurface, AlertRed, AlertRed)
          "Alerted" -> Triple(if (isSelected) AmberGlow else DarkSurface, WarningAmber, WarningAmber)
          "Normal" -> Triple(if (isSelected) GreenGlow else DarkSurface, CyberGreen, CyberGreen)
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
          Icon(Icons.Default.Dns, contentDescription = null, tint = TextMuted, modifier = Modifier.size(36.dp))
          Spacer(modifier = Modifier.height(8.dp))
          Text("No hay sesiones que coincidan con el criterio seleccionado.", color = TextMuted, fontSize = 11.sp)
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
            onPromptBlock = { pendingBlockTarget = session.macAddress to session.deviceId },
            onUnblock = { onUnblockMacConfirmed(session.macAddress, session.deviceId) }
          )
        }
      }
    }
  }

  // Invariante 5: Diálogo de Confirmación Obligatorio para Acciones Destructivas / Bloqueo
  pendingBlockTarget?.let { (mac, devId) ->
    AlertDialog(
      onDismissRequest = { pendingBlockTarget = null },
      containerColor = DarkSurface,
      titleContentColor = AlertRed,
      textContentColor = TextSecondary,
      icon = { Icon(Icons.Default.WarningAmber, contentDescription = null, tint = AlertRed) },
      title = { Text("Confirmación Requerida (Invariante 5)", fontSize = 13.sp, fontWeight = FontWeight.Bold) },
      text = {
        Text(
          "¿Confirmas el aislamiento y bloqueo en cascada para la dirección MAC $mac y el device_id $devId? Esta acción suspenderá inmediatamente el tráfico y revocará todas las identidades asociadas.",
          fontSize = 11.sp,
          color = TextPrimary,
          lineHeight = 15.sp
        )
      },
      confirmButton = {
        Button(
          onClick = {
            onBlockMacConfirmed(mac, devId)
            pendingBlockTarget = null
          },
          colors = ButtonDefaults.buttonColors(containerColor = AlertRed, contentColor = Color.White)
        ) {
          Text("Confirmar Bloqueo", fontSize = 11.sp, fontWeight = FontWeight.Bold)
        }
      },
      dismissButton = {
        TextButton(onClick = { pendingBlockTarget = null }) {
          Text("Cancelar", color = TextSecondary, fontSize = 11.sp)
        }
      }
    )
  }
}

@Composable
fun SessionItemCard(
  session: MonitoredSessionEntity,
  onPromptBlock: () -> Unit,
  onUnblock: () -> Unit
) {
  var isExpanded by remember { mutableStateOf(false) }
  val isBlocked = session.isMacBlocked || session.currentStatus == "Blocked"
  val isAlerted = session.isInObservation || session.currentStatus == "Alerted"

  val (borderColor, statusBadgeBg, statusBadgeColor, statusLabel) = when {
    isBlocked -> Quadruple(AlertRed, RedGlow, AlertRed, "BLOQUEADO")
    isAlerted -> Quadruple(WarningAmber, AmberGlow, WarningAmber, "EN OBSERVACIÓN")
    else -> Quadruple(CyberGreen, GreenGlow, CyberGreen, "NOMINAL")
  }

  Card(
    modifier = Modifier
      .fillMaxWidth()
      .testTag("session_card_${session.macAddress}"),
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
          Text(session.ipAddress, fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
        }

        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
          if (isBlocked) {
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
              onClick = onPromptBlock,
              modifier = Modifier.height(26.dp),
              contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
              colors = ButtonDefaults.buttonColors(containerColor = AlertRed, contentColor = Color.White)
            ) {
              Text("Bloquear (Inv 5)", fontSize = 9.sp, fontWeight = FontWeight.Bold)
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
      Text("device_id: ${session.deviceId}", fontSize = 10.sp, color = CyberCyan, fontFamily = FontFamily.Monospace)
      Text("MAC Física: ${session.macAddress} | Lease DHCP: ${session.dhcpLeaseSeconds}s", fontSize = 10.sp, color = TextMuted, fontFamily = FontFamily.Monospace)

      if (session.emailsUsedCsv.isNotBlank()) {
        Spacer(modifier = Modifier.height(2.dp))
        Text("Emails Vinculados: ${session.emailsUsedCsv}", fontSize = 10.sp, color = TextPrimary)
      }

      if (session.detectedAnomaliesCsv.isNotBlank()) {
        Text("⚠️ Anomalías: ${session.detectedAnomaliesCsv}", fontSize = 9.sp, color = WarningAmber, fontWeight = FontWeight.SemiBold)
      }

      AnimatedVisibility(visible = isExpanded) {
        Column(modifier = Modifier.padding(top = 8.dp)) {
          Divider(color = DarkBorder, modifier = Modifier.padding(vertical = 4.dp))
          Text("Telemetría Profunda de Fingerprint (Invariante 1):", fontSize = 10.sp, color = CyberCyan, fontWeight = FontWeight.Bold)
          Text("• Huella Canvas: ${session.browserFingerprint}", fontSize = 9.sp, color = TextSecondary, fontFamily = FontFamily.Monospace)
          Text("• Huella TLS JA3: ${session.ja3Fingerprint}", fontSize = 9.sp, color = TextSecondary, fontFamily = FontFamily.Monospace)
          Text("• Huella DHCP: ${session.dhcpFingerprint}", fontSize = 9.sp, color = TextSecondary, fontFamily = FontFamily.Monospace)
          Text("• Duración de Conexión: ${session.durationSeconds} segundos", fontSize = 9.sp, color = TextSecondary)
          if (session.visitedUrlsCsv.isNotBlank()) {
            Text("• Destinos Auditados: ${session.visitedUrlsCsv}", fontSize = 9.sp, color = WarningAmber, fontFamily = FontFamily.Monospace)
          }
        }
      }
    }
  }
}

data class Quadruple<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)
