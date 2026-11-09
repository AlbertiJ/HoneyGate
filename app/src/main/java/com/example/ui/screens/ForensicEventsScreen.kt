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
import com.example.data.local.entity.ForensicEventEntity
import com.example.ui.theme.*

@Composable
fun ForensicEventsScreen(
  events: List<ForensicEventEntity>,
  selectedFilter: String,
  searchQuery: String,
  blockedCount: Int,
  alertedCount: Int,
  normalCount: Int,
  onFilterSelected: (String) -> Unit,
  onSearchQueryChanged: (String) -> Unit,
  onBlockMac: (String) -> Unit,
  onDeleteEvent: (Long) -> Unit
) {
  var selectedEventForDetail by remember { mutableStateOf<ForensicEventEntity?>(null) }

  Column(
    modifier = Modifier
      .fillMaxSize()
      .padding(horizontal = 14.dp, vertical = 8.dp)
  ) {
    // 1. Tarjetas de Métricas de Estados Forenses
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

    // 2. Barra de Búsqueda
    OutlinedTextField(
      value = searchQuery,
      onValueChange = onSearchQueryChanged,
      modifier = Modifier
        .fillMaxWidth()
        .testTag("search_forensic_events"),
      placeholder = { Text("Buscar por IP, MAC, usuario o técnica MITRE...", fontSize = 12.sp, color = TextMuted) },
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

    // 3. Filtros Visuales (Chips de Estado 'Blocked', 'Alerted', 'Normal')
    LazyRow(
      modifier = Modifier.fillMaxWidth(),
      horizontalArrangement = Arrangement.spacedBy(8.dp),
      verticalAlignment = Alignment.CenterVertically
    ) {
      val filterOptions = listOf(
        "All" to "Todos los Eventos",
        "Blocked" to "Blocked (Contención)",
        "Alerted" to "Alerted (En Observación)",
        "Normal" to "Normal (Nominal)"
      )

      items(filterOptions) { (key, label) ->
        val isSelected = selectedFilter == key
        val (chipBg, chipBorder, chipText) = when (key) {
          "Blocked" -> Triple(if (isSelected) RedGlow else DarkSurface, AlertRed, AlertRed)
          "Alerted" -> Triple(if (isSelected) Color(0x33FFCC00) else DarkSurface, WarningAmber, WarningAmber)
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

    // 4. Listado Reactivo de Eventos Forenses desde Room
    if (events.isEmpty()) {
      Box(
        modifier = Modifier
          .fillMaxSize()
          .padding(32.dp),
        contentAlignment = Alignment.Center
      ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
          Icon(Icons.Default.FilterListOff, contentDescription = null, tint = TextMuted, modifier = Modifier.size(48.dp))
          Spacer(modifier = Modifier.height(10.dp))
          Text("No hay eventos forenses para el filtro actual", color = TextSecondary, fontSize = 13.sp)
          Text("Intenta cambiar el filtro o genera nuevos eventos desde Honeygate", color = TextMuted, fontSize = 11.sp)
        }
      }
    } else {
      LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        contentPadding = PaddingValues(bottom = 16.dp)
      ) {
        items(events, key = { it.id }) { event ->
          ForensicEventItem(
            event = event,
            onClick = { selectedEventForDetail = event },
            onBlockMac = { onBlockMac(event.macAddress) },
            onDelete = { onDeleteEvent(event.id) }
          )
        }
      }
    }
  }

  // Modal / BottomSheet de Detalle Forense Completo
  selectedEventForDetail?.let { event ->
    AlertDialog(
      onDismissRequest = { selectedEventForDetail = null },
      containerColor = DarkSurface,
      titleContentColor = TextPrimary,
      textContentColor = TextSecondary,
      title = {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          StatusBadge(status = event.status)
          Text(event.title, fontSize = 14.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
        }
      },
      text = {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Text("Hora del Evento: ${event.dateFormatted}", fontSize = 11.sp, color = TextMuted)
          Text("Descripción:", fontWeight = FontWeight.SemiBold, fontSize = 12.sp, color = TextPrimary)
          Text(event.description, fontSize = 12.sp, color = TextSecondary)
          
          Divider(color = DarkBorder)
          
          Text("Matriz de Correlación:", fontWeight = FontWeight.SemiBold, fontSize = 12.sp, color = CyberCyan)
          Text("• IP de Origen: ${event.sourceIp}", fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
          Text("• Dirección MAC: ${event.macAddress}", fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
          event.associatedEmail?.let {
            Text("• Usuario/Email: $it", fontSize = 11.sp, color = TextPrimary)
          }
          Text("• MITRE ATT&CK: ${event.mitreTechnique}", fontSize = 11.sp, color = WarningAmber)
          event.rawPayload?.let {
            Text("• Payload Crudo: $it", fontSize = 10.sp, color = AlertRed, fontFamily = FontFamily.Monospace)
          }
        }
      },
      confirmButton = {
        Button(
          onClick = {
            onBlockMac(event.macAddress)
            selectedEventForDetail = null
          },
          colors = ButtonDefaults.buttonColors(containerColor = AlertRed, contentColor = Color.White)
        ) {
          Text("Bloquear MAC en Cascada", fontSize = 11.sp, fontWeight = FontWeight.Bold)
        }
      },
      dismissButton = {
        TextButton(onClick = { selectedEventForDetail = null }) {
          Text("Cerrar", color = TextSecondary, fontSize = 12.sp)
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
    colors = CardDefaults.cardColors(containerColor = if (isSelected) color.copy(alpha = 0.15f) else DarkSurface),
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
  event: ForensicEventEntity,
  onClick: () -> Unit,
  onBlockMac: () -> Unit,
  onDelete: () -> Unit
) {
  val (borderColor, _) = when (event.status) {
    "Blocked" -> AlertRed to RedGlow
    "Alerted" -> WarningAmber to Color(0x33FFCC00)
    else -> CyberGreen to GreenGlow
  }

  Card(
    modifier = Modifier
      .fillMaxWidth()
      .clickable(onClick = onClick)
      .testTag("event_item_${event.id}"),
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
          StatusBadge(status = event.status)
          Text(event.title, fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 13.sp)
        }
        Text(event.dateFormatted, fontSize = 10.sp, color = TextMuted)
      }

      Spacer(modifier = Modifier.height(6.dp))
      Text(event.description, fontSize = 12.sp, color = TextSecondary, lineHeight = 16.sp, maxLines = 3)

      Spacer(modifier = Modifier.height(8.dp))
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Column {
          Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("IP: ${event.sourceIp}", fontSize = 10.sp, color = CyberCyan, fontFamily = FontFamily.Monospace)
            Text("MAC: ${event.macAddress}", fontSize = 10.sp, color = TextMuted, fontFamily = FontFamily.Monospace)
          }
          Text(event.mitreTechnique, fontSize = 10.sp, color = WarningAmber)
        }

        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
          if (event.status != "Blocked") {
            OutlinedButton(
              onClick = onBlockMac,
              modifier = Modifier.height(28.dp),
              contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
              colors = ButtonDefaults.outlinedButtonColors(contentColor = AlertRed),
              border = androidx.compose.foundation.BorderStroke(1.dp, AlertRed)
            ) {
              Text("Bloquear", fontSize = 10.sp, fontWeight = FontWeight.Bold)
            }
          }
          IconButton(onClick = onDelete, modifier = Modifier.size(28.dp)) {
            Icon(Icons.Default.DeleteOutline, contentDescription = "Eliminar", tint = TextMuted, modifier = Modifier.size(16.dp))
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
    "Alerted" -> Triple(Color(0x33FFCC00), WarningAmber, "ALERTED")
    else -> Triple(GreenGlow, CyberGreen, "NORMAL")
  }

  Surface(
    shape = RoundedCornerShape(4.dp),
    color = bg,
    border = androidx.compose.foundation.BorderStroke(1.dp, textColor.copy(alpha = 0.6f))
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
