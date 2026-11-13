package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
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
import com.example.data.local.entity.ForensicEvent
import com.example.ui.theme.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ForensicEventsScreen(
  events: List<ForensicEvent>,
  selectedFilter: String,
  searchQuery: String,
  blockedCount: Int,
  alertedCount: Int,
  normalCount: Int,
  isOnline: Boolean,
  onFilterSelected: (String) -> Unit,
  onSearchQueryChanged: (String) -> Unit,
  onIsolateIpConfirmed: (String, String) -> Unit,
  onDeleteEvent: (Long) -> Unit,
  onRefreshFromDaemon: () -> Unit
) {
  var selectedEventForDetail by remember { mutableStateOf<ForensicEvent?>(null) }
  var pendingIsolateTarget by remember { mutableStateOf<Pair<String, String>?>(null) }

  Column(
    modifier = Modifier
      .fillMaxSize()
      .padding(horizontal = 14.dp, vertical = 8.dp)
  ) {
    Row(
      modifier = Modifier
        .fillMaxWidth()
        .padding(bottom = 10.dp),
      horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
      StatusMetricCard(
        label = "Blocked",
        count = blockedCount,
        color = AlertRed,
        isSelected = selectedFilter == "Blocked",
        onClick = { onFilterSelected(if (selectedFilter == "Blocked") "All" else "Blocked") },
        modifier = Modifier.weight(1f)
      )
      StatusMetricCard(
        label = "Alerted",
        count = alertedCount,
        color = WarningAmber,
        isSelected = selectedFilter == "Alerted",
        onClick = { onFilterSelected(if (selectedFilter == "Alerted") "All" else "Alerted") },
        modifier = Modifier.weight(1f)
      )
      StatusMetricCard(
        label = "Normal",
        count = normalCount,
        color = CyberGreen,
        isSelected = selectedFilter == "Normal",
        onClick = { onFilterSelected(if (selectedFilter == "Normal") "All" else "Normal") },
        modifier = Modifier.weight(1f)
      )
    }

    val totalCount = blockedCount + alertedCount + normalCount
    if (totalCount > 0) {
      val blockedRatio = blockedCount.toFloat() / totalCount
      val alertedRatio = alertedCount.toFloat() / totalCount
      val normalRatio = normalCount.toFloat() / totalCount

      Column(modifier = Modifier.fillMaxWidth().padding(bottom = 10.dp)) {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically
        ) {
          Text(
            "Distribución de Eventos ($totalCount)",
            fontSize = 10.sp,
            color = TextSecondary,
            fontWeight = FontWeight.SemiBold
          )
          Text(
            "${(blockedRatio * 100).toInt()}% Crít | ${(alertedRatio * 100).toInt()}% Alerta | ${(normalRatio * 100).toInt()}% Info",
            fontSize = 10.sp,
            color = CyberCyan,
            fontFamily = FontFamily.Monospace
          )
        }
        Spacer(modifier = Modifier.height(4.dp))
        Row(
          modifier = Modifier
            .fillMaxWidth()
            .height(6.dp)
            .clip(RoundedCornerShape(3.dp))
            .background(DarkSurfaceVariant)
        ) {
          if (blockedRatio > 0f) {
            Box(modifier = Modifier.weight(blockedRatio.coerceAtLeast(0.01f)).fillMaxHeight().background(AlertRed))
          }
          if (alertedRatio > 0f) {
            Box(modifier = Modifier.weight(alertedRatio.coerceAtLeast(0.01f)).fillMaxHeight().background(WarningAmber))
          }
          if (normalRatio > 0f) {
            Box(modifier = Modifier.weight(normalRatio.coerceAtLeast(0.01f)).fillMaxHeight().background(CyberGreen))
          }
        }
      }
    }

    Row(
      modifier = Modifier.fillMaxWidth(),
      horizontalArrangement = Arrangement.spacedBy(8.dp),
      verticalAlignment = Alignment.CenterVertically
    ) {
      OutlinedTextField(
        value = searchQuery,
        onValueChange = onSearchQueryChanged,
        modifier = Modifier
          .weight(1f)
          .testTag("search_forensic_events"),
        placeholder = { Text("Buscar IP, device_id, event_type o MITRE...", fontSize = 12.sp, color = TextMuted) },
        leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(20.dp)) },
        trailingIcon = {
          if (searchQuery.isNotEmpty()) {
            IconButton(onClick = { onSearchQueryChanged("") }) {
              Icon(Icons.Default.Close, contentDescription = "Limpiar", tint = TextSecondary, modifier = Modifier.size(18.dp))
            }
          }
        },
        singleLine = true,
        textStyle = androidx.compose.ui.text.TextStyle(color = TextPrimary, fontSize = 13.sp),
        colors = OutlinedTextFieldDefaults.colors(
          focusedContainerColor = DarkSurface,
          unfocusedContainerColor = DarkSurface,
          focusedBorderColor = CyberCyan,
          unfocusedBorderColor = DarkBorder
        ),
        shape = RoundedCornerShape(10.dp)
      )

      IconButton(
        onClick = onRefreshFromDaemon,
        modifier = Modifier
          .size(48.dp)
          .clip(RoundedCornerShape(10.dp))
          .background(DarkSurface)
          .testTag("refresh_events_button")
      ) {
        Icon(Icons.Default.Refresh, contentDescription = "Actualizar eventos del daemon", tint = CyberCyan)
      }
    }

    Spacer(modifier = Modifier.height(10.dp))

    LazyRow(
      modifier = Modifier.fillMaxWidth(),
      horizontalArrangement = Arrangement.spacedBy(8.dp),
      verticalAlignment = Alignment.CenterVertically
    ) {
      val filterOptions = listOf(
        "All" to "Todos",
        "Blocked" to "Críticos / Bloqueo",
        "Alerted" to "Advertencias",
        "Normal" to "Informativos"
      )

      items(filterOptions) { (key, label) ->
        val isSelected = selectedFilter == key
        val (chipBg, chipBorder, chipText) = when (key) {
          "Blocked" -> Triple(if (isSelected) RedGlow else DarkSurface, AlertRed, AlertRed)
          "Alerted" -> Triple(if (isSelected) AmberGlow else DarkSurface, WarningAmber, WarningAmber)
          "Normal" -> Triple(if (isSelected) GreenGlow else DarkSurface, CyberGreen, CyberGreen)
          else -> Triple(if (isSelected) CyanGlow else DarkSurface, CyberCyan, CyberCyan)
        }

        FilterChip(
          selected = isSelected,
          onClick = { onFilterSelected(key) },
          label = { Text(label, fontSize = 11.sp, fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal) },
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
          ),
          modifier = Modifier.testTag("filter_chip_$key")
        )
      }
    }

    Spacer(modifier = Modifier.height(8.dp))

    if (events.isEmpty()) {
      Box(
        modifier = Modifier
          .fillMaxSize()
          .padding(32.dp),
        contentAlignment = Alignment.Center
      ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
          Icon(
            imageVector = if (isOnline) Icons.Default.VerifiedUser else Icons.Default.CloudOff,
            contentDescription = null,
            tint = TextMuted,
            modifier = Modifier.size(44.dp)
          )
          Spacer(modifier = Modifier.height(10.dp))
          Text(
            text = if (isOnline) "Sin eventos en el daemon" else "Sin conexión — caché de eventos vacía",
            color = TextSecondary,
            fontSize = 13.sp
          )
          Text(
            text = "Conectá el daemon y sincronizá desde GET /api/events para ver telemetría real.",
            color = TextMuted,
            fontSize = 11.sp
          )
        }
      }
    } else {
      LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        contentPadding = PaddingValues(bottom = 20.dp)
      ) {
        items(events, key = { it.id }) { event ->
          ForensicEventItem(
            event = event,
            onClick = { selectedEventForDetail = event },
            onPromptIsolate = { pendingIsolateTarget = event.sourceIp to event.deviceId },
            onDelete = { onDeleteEvent(event.id) }
          )
        }
      }
    }
  }

  pendingIsolateTarget?.let { (ip, devId) ->
    AlertDialog(
      onDismissRequest = { pendingIsolateTarget = null },
      containerColor = DarkSurface,
      titleContentColor = AlertRed,
      textContentColor = TextSecondary,
      icon = { Icon(Icons.Default.WarningAmber, contentDescription = null, tint = AlertRed) },
      title = { Text("Confirmación Requerida (Invariante 5)", fontSize = 14.sp, fontWeight = FontWeight.Bold) },
      text = {
        Text(
          "¿Confirmas aislar la IP $ip (device_id: ${devId.ifBlank { "sin device_id" }}) en el daemon mediante POST /api/isolate?",
          fontSize = 12.sp,
          color = TextPrimary,
          lineHeight = 16.sp
        )
      },
      confirmButton = {
        Button(
          onClick = {
            onIsolateIpConfirmed(ip, devId)
            pendingIsolateTarget = null
          },
          colors = ButtonDefaults.buttonColors(containerColor = AlertRed, contentColor = Color.White)
        ) {
          Text("Confirmar Aislamiento", fontSize = 11.sp, fontWeight = FontWeight.Bold)
        }
      },
      dismissButton = {
        TextButton(onClick = { pendingIsolateTarget = null }) {
          Text("Cancelar", color = TextSecondary, fontSize = 11.sp)
        }
      }
    )
  }

  selectedEventForDetail?.let { event ->
    AlertDialog(
      onDismissRequest = { selectedEventForDetail = null },
      containerColor = DarkSurface,
      titleContentColor = TextPrimary,
      textContentColor = TextSecondary,
      title = {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          StatusBadge(status = event.eventType, severity = event.severity)
          Text(event.rawEventType.ifBlank { event.category }, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
        }
      },
      text = {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
          Text("Descripción:", fontWeight = FontWeight.SemiBold, fontSize = 11.sp, color = TextPrimary)
          Text(event.description, fontSize = 11.sp, color = TextSecondary, lineHeight = 15.sp)

          Divider(color = DarkBorder, modifier = Modifier.padding(vertical = 4.dp))

          Text("Campos del Evento (/api/events):", fontWeight = FontWeight.SemiBold, fontSize = 11.sp, color = CyberCyan)
          event.daemonEventId?.let { Text("• id: $it | modo: ${event.mode}", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = TextPrimary) }
          event.sessionId?.let { Text("• session_id: $it", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = TextPrimary) }
          if (event.deviceId.isNotBlank()) {
            Text("• device_id: ${event.deviceId}", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
          }
          if (event.sourceIp.isNotBlank()) {
            Text("• ip: ${event.sourceIp}", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
          }
          if (event.macAddress.isNotBlank()) {
            Text("• mac: ${event.macAddress}", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
          }
          if (event.mitreTechnique.isNotBlank()) {
            Text("• mitre_technique: ${event.mitreTechnique}", fontSize = 10.sp, color = WarningAmber)
          }
          event.honeytokenTouched?.let {
            Text("• honeytoken_touched: $it", fontSize = 10.sp, color = AlertRed, fontWeight = FontWeight.Bold)
          }
        }
      },
      confirmButton = {
        if (event.sourceIp.isNotBlank() && event.eventType != "Blocked") {
          Button(
            onClick = {
              pendingIsolateTarget = event.sourceIp to event.deviceId
              selectedEventForDetail = null
            },
            colors = ButtonDefaults.buttonColors(containerColor = AlertRed, contentColor = Color.White)
          ) {
            Text("Aislar IP", fontSize = 11.sp, fontWeight = FontWeight.Bold)
          }
        }
      },
      dismissButton = {
        TextButton(onClick = { selectedEventForDetail = null }) {
          Text("Cerrar", color = TextSecondary, fontSize = 11.sp)
        }
      }
    )
  }
}

@Composable
fun StatusMetricCard(
  label: String,
  count: Int,
  color: Color,
  isSelected: Boolean,
  onClick: () -> Unit,
  modifier: Modifier = Modifier
) {
  Card(
    modifier = modifier
      .clickable(onClick = onClick)
      .testTag("metric_card_$label"),
    shape = RoundedCornerShape(10.dp),
    colors = CardDefaults.cardColors(containerColor = if (isSelected) color.copy(alpha = 0.12f) else DarkSurface),
    border = androidx.compose.foundation.BorderStroke(1.dp, if (isSelected) color else DarkBorder)
  ) {
    Column(modifier = Modifier.padding(10.dp)) {
      Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        Box(modifier = Modifier.size(6.dp).clip(CircleShape).background(color))
        Text(label, fontSize = 10.sp, color = TextSecondary, fontWeight = FontWeight.SemiBold)
      }
      Spacer(modifier = Modifier.height(4.dp))
      Text(
        text = count.toString(),
        fontSize = 20.sp,
        fontWeight = FontWeight.Bold,
        color = color
      )
    }
  }
}

@Composable
fun ForensicEventItem(
  event: ForensicEvent,
  onClick: () -> Unit,
  onPromptIsolate: () -> Unit,
  onDelete: () -> Unit
) {
  val borderColor = when (event.eventType) {
    "Blocked" -> AlertRed
    "Alerted" -> WarningAmber
    else -> CyberGreen
  }

  val dateStr = if (event.dateFormatted.isNotBlank()) {
    event.dateFormatted
  } else {
    SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(event.timestamp))
  }

  Card(
    modifier = Modifier
      .fillMaxWidth()
      .clickable(onClick = onClick)
      .testTag("event_item_${event.id}"),
    shape = RoundedCornerShape(10.dp),
    colors = CardDefaults.cardColors(containerColor = DarkSurface),
    border = androidx.compose.foundation.BorderStroke(1.dp, borderColor.copy(alpha = 0.35f))
  ) {
    Column(modifier = Modifier.padding(12.dp)) {
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Row(
          verticalAlignment = Alignment.CenterVertically,
          horizontalArrangement = Arrangement.spacedBy(6.dp),
          modifier = Modifier.weight(1f)
        ) {
          StatusBadge(status = event.eventType, severity = event.severity)
          Text(
            text = event.rawEventType.ifBlank { event.category },
            fontWeight = FontWeight.Bold,
            color = TextPrimary,
            fontSize = 11.sp,
            maxLines = 1
          )
          if (event.isDemo) {
            Surface(shape = RoundedCornerShape(4.dp), color = AmberGlow) {
              Text("DEMO", color = WarningAmber, fontSize = 8.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp))
            }
          }
        }
        Text(dateStr, fontSize = 10.sp, color = TextMuted)
      }

      Spacer(modifier = Modifier.height(6.dp))
      Text(event.description, fontSize = 11.sp, color = TextSecondary, lineHeight = 15.sp, maxLines = 3)

      Spacer(modifier = Modifier.height(6.dp))
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Column(modifier = Modifier.weight(1f)) {
          Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (event.sourceIp.isNotBlank()) {
              Text("IP: ${event.sourceIp}", fontSize = 10.sp, color = CyberCyan, fontFamily = FontFamily.Monospace)
            }
            if (event.macAddress.isNotBlank()) {
              Text("MAC: ${event.macAddress}", fontSize = 10.sp, color = TextMuted, fontFamily = FontFamily.Monospace)
            }
          }
          if (event.deviceId.isNotBlank()) {
            Text("device_id: ${event.deviceId}", fontSize = 9.sp, color = TextMuted, fontFamily = FontFamily.Monospace)
          }
          if (event.mitreTechnique.isNotBlank()) {
            Text("MITRE: ${event.mitreTechnique}", fontSize = 9.sp, color = WarningAmber)
          }
          event.honeytokenTouched?.let {
            Text("Honeytoken: $it", fontSize = 9.sp, color = AlertRed, fontWeight = FontWeight.Bold)
          }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
          if (event.sourceIp.isNotBlank() && event.eventType != "Blocked") {
            OutlinedButton(
              onClick = onPromptIsolate,
              modifier = Modifier.height(26.dp),
              contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
              colors = ButtonDefaults.outlinedButtonColors(contentColor = AlertRed),
              border = androidx.compose.foundation.BorderStroke(1.dp, AlertRed.copy(alpha = 0.6f))
            ) {
              Text("Aislar", fontSize = 9.sp, fontWeight = FontWeight.Bold)
            }
          }
          IconButton(onClick = onDelete, modifier = Modifier.size(26.dp)) {
            Icon(Icons.Default.DeleteOutline, contentDescription = "Limpiar caché", tint = TextMuted, modifier = Modifier.size(15.dp))
          }
        }
      }
    }
  }
}

@Composable
fun StatusBadge(status: String, severity: String = "") {
  val (bg, textColor, label) = when (status) {
    "Blocked" -> Triple(RedGlow, AlertRed, if (severity.isNotBlank()) severity.uppercase() else "CRITICAL")
    "Alerted" -> Triple(AmberGlow, WarningAmber, if (severity.isNotBlank()) severity.uppercase() else "WARNING")
    else -> Triple(GreenGlow, CyberGreen, if (severity.isNotBlank()) severity.uppercase() else "INFO")
  }

  Surface(
    shape = RoundedCornerShape(4.dp),
    color = bg,
    border = androidx.compose.foundation.BorderStroke(1.dp, textColor.copy(alpha = 0.5f))
  ) {
    Text(
      text = label,
      color = textColor,
      fontSize = 9.sp,
      fontWeight = FontWeight.Bold,
      modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
      letterSpacing = 0.5.sp
    )
  }
}
