package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
  onFilterSelected: (String) -> Unit,
  onSearchQueryChanged: (String) -> Unit,
  onBlockMacConfirmed: (String, String) -> Unit,
  onDeleteEvent: (Long) -> Unit
) {
  var selectedEventForDetail by remember { mutableStateOf<ForensicEvent?>(null) }
  var pendingBlockMacTarget by remember { mutableStateOf<Pair<String, String>?>(null) } // mac to deviceId

  Column(
    modifier = Modifier
      .fillMaxSize()
      .padding(horizontal = 14.dp, vertical = 8.dp)
  ) {
    // 1. Tarjetas de Métricas de Estados Forenses (Colores calmados para confort visual)
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

    // Barra Táctica de Distribución de Eventos (Eye-Care UX)
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
            "Distribución Táctica de Amenazas ($totalCount eventos)",
            fontSize = 10.sp,
            color = TextSecondary,
            fontWeight = FontWeight.SemiBold
          )
          Text(
            "${(blockedRatio * 100).toInt()}% Blocked | ${(alertedRatio * 100).toInt()}% Alerted | ${(normalRatio * 100).toInt()}% Normal",
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
            Box(
              modifier = Modifier
                .weight(blockedRatio.coerceAtLeast(0.01f))
                .fillMaxHeight()
                .background(AlertRed)
            )
          }
          if (alertedRatio > 0f) {
            Box(
              modifier = Modifier
                .weight(alertedRatio.coerceAtLeast(0.01f))
                .fillMaxHeight()
                .background(WarningAmber)
            )
          }
          if (normalRatio > 0f) {
            Box(
              modifier = Modifier
                .weight(normalRatio.coerceAtLeast(0.01f))
                .fillMaxHeight()
                .background(CyberGreen)
            )
          }
        }
      }
    }

    // 2. Barra de Búsqueda Intuitiva
    OutlinedTextField(
      value = searchQuery,
      onValueChange = onSearchQueryChanged,
      modifier = Modifier
        .fillMaxWidth()
        .testTag("search_forensic_events"),
      placeholder = { Text("Buscar por IP, MAC, device_id o técnica MITRE...", fontSize = 12.sp, color = TextMuted) },
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

    Spacer(modifier = Modifier.height(10.dp))

    // 3. Fila de Filtros (Chips) para alternar entre 'Blocked', 'Alerted', y 'Normal'
    LazyRow(
      modifier = Modifier.fillMaxWidth(),
      horizontalArrangement = Arrangement.spacedBy(8.dp),
      verticalAlignment = Alignment.CenterVertically
    ) {
      val filterOptions = listOf(
        "All" to "Todos los Eventos",
        "Blocked" to "Blocked (Contención)",
        "Alerted" to "Alerted (Observación)",
        "Normal" to "Normal (Nominal)"
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

    // 4. LazyColumn con el listado de eventos forenses
    if (events.isEmpty()) {
      Box(
        modifier = Modifier
          .fillMaxSize()
          .padding(32.dp),
        contentAlignment = Alignment.Center
      ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
          Icon(Icons.Default.FilterListOff, contentDescription = null, tint = TextMuted, modifier = Modifier.size(44.dp))
          Spacer(modifier = Modifier.height(10.dp))
          Text("No hay eventos forenses para el filtro seleccionado", color = TextSecondary, fontSize = 13.sp)
          Text("Modifica el filtro superior o genera actividad desde HoneyGate", color = TextMuted, fontSize = 11.sp)
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
            onPromptBlock = { pendingBlockMacTarget = event.macAddress to event.deviceId },
            onDelete = { onDeleteEvent(event.id) }
          )
        }
      }
    }
  }

  // Invariante 5: Diálogo de Confirmación Obligatorio para Acciones Destructivas / Bloqueo
  pendingBlockMacTarget?.let { (mac, devId) ->
    AlertDialog(
      onDismissRequest = { pendingBlockMacTarget = null },
      containerColor = DarkSurface,
      titleContentColor = AlertRed,
      textContentColor = TextSecondary,
      icon = { Icon(Icons.Default.WarningAmber, contentDescription = null, tint = AlertRed) },
      title = { Text("Confirmación Requerida (Invariante 5)", fontSize = 14.sp, fontWeight = FontWeight.Bold) },
      text = {
        Text(
          "¿Confirmas el aislamiento y bloqueo en cascada para la dirección MAC $mac y el device_id $devId? Esta acción suspenderá inmediatamente todo tráfico y revocará credenciales asociadas.",
          fontSize = 12.sp,
          color = TextPrimary,
          lineHeight = 16.sp
        )
      },
      confirmButton = {
        Button(
          onClick = {
            onBlockMacConfirmed(mac, devId)
            pendingBlockMacTarget = null
          },
          colors = ButtonDefaults.buttonColors(containerColor = AlertRed, contentColor = Color.White)
        ) {
          Text("Confirmar Bloqueo", fontSize = 11.sp, fontWeight = FontWeight.Bold)
        }
      },
      dismissButton = {
        TextButton(onClick = { pendingBlockMacTarget = null }) {
          Text("Cancelar", color = TextSecondary, fontSize = 11.sp)
        }
      }
    )
  }

  // Modal de Detalle Forense Completo
  selectedEventForDetail?.let { event ->
    AlertDialog(
      onDismissRequest = { selectedEventForDetail = null },
      containerColor = DarkSurface,
      titleContentColor = TextPrimary,
      textContentColor = TextSecondary,
      title = {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          StatusBadge(status = event.eventType)
          Text(event.category, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
        }
      },
      text = {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
          Text("Descripción:", fontWeight = FontWeight.SemiBold, fontSize = 11.sp, color = TextPrimary)
          Text(event.description, fontSize = 11.sp, color = TextSecondary, lineHeight = 15.sp)
          
          Divider(color = DarkBorder, modifier = Modifier.padding(vertical = 4.dp))
          
          Text("Identificadores (Invariante 1 - Fingerprint Compuesto):", fontWeight = FontWeight.SemiBold, fontSize = 11.sp, color = CyberCyan)
          Text("• device_id: ${event.deviceId.ifEmpty { "dev_composite_unregistered" }}", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
          Text("• IP Origen: ${event.sourceIp}", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
          Text("• MAC Origen: ${event.macAddress}", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
          Text("• MITRE ATT&CK: ${event.mitreTechnique}", fontSize = 10.sp, color = WarningAmber)
          
          event.honeytokenTouched?.let {
            Text("• Honeytoken Tocado: $it", fontSize = 10.sp, color = AlertRed, fontWeight = FontWeight.Bold)
          }
        }
      },
      confirmButton = {
        if (event.eventType != "Blocked") {
          Button(
            onClick = {
              pendingBlockMacTarget = event.macAddress to event.deviceId
              selectedEventForDetail = null
            },
            colors = ButtonDefaults.buttonColors(containerColor = AlertRed, contentColor = Color.White)
          ) {
            Text("Bloquear con Confirmación", fontSize = 11.sp, fontWeight = FontWeight.Bold)
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
  onPromptBlock: () -> Unit,
  onDelete: () -> Unit
) {
  val (borderColor, _) = when (event.eventType) {
    "Blocked" -> AlertRed to RedGlow
    "Alerted" -> WarningAmber to AmberGlow
    else -> CyberGreen to GreenGlow
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
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
          StatusBadge(status = event.eventType)
          Text(event.category, fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 12.sp)
          if (event.isCorrelated) {
            Surface(
              shape = RoundedCornerShape(4.dp),
              color = CyanGlow,
              border = androidx.compose.foundation.BorderStroke(0.5.dp, CyberCyan)
            ) {
              Text("CORRELACIONADO", color = CyberCyan, fontSize = 8.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp))
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
            Text("IP: ${event.sourceIp}", fontSize = 10.sp, color = CyberCyan, fontFamily = FontFamily.Monospace)
            Text("MAC: ${event.macAddress}", fontSize = 10.sp, color = TextMuted, fontFamily = FontFamily.Monospace)
          }
          if (event.deviceId.isNotBlank()) {
            Text("device_id: ${event.deviceId}", fontSize = 9.sp, color = TextMuted, fontFamily = FontFamily.Monospace)
          }
          Text(event.mitreTechnique, fontSize = 9.sp, color = WarningAmber)
          event.honeytokenTouched?.let {
            Text("⚠️ Honeytoken: $it", fontSize = 9.sp, color = AlertRed, fontWeight = FontWeight.Bold)
          }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
          if (event.eventType != "Blocked") {
            OutlinedButton(
              onClick = onPromptBlock,
              modifier = Modifier.height(26.dp),
              contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
              colors = ButtonDefaults.outlinedButtonColors(contentColor = AlertRed),
              border = androidx.compose.foundation.BorderStroke(1.dp, AlertRed.copy(alpha = 0.6f))
            ) {
              Text("Bloquear", fontSize = 9.sp, fontWeight = FontWeight.Bold)
            }
          }
          IconButton(onClick = onDelete, modifier = Modifier.size(26.dp)) {
            Icon(Icons.Default.DeleteOutline, contentDescription = "Eliminar", tint = TextMuted, modifier = Modifier.size(15.dp))
          }
        }
      }
    }
  }
}

@Composable
fun StatusBadge(status: String) {
  val (bg, textColor, label) = when (status) {
    "Blocked" -> Triple(RedGlow, AlertRed, "BLOCKED")
    "Alerted" -> Triple(AmberGlow, WarningAmber, "ALERTED")
    else -> Triple(GreenGlow, CyberGreen, "NORMAL")
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
