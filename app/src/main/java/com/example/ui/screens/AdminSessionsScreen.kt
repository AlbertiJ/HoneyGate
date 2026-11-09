package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
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
  onBlockMac: (String) -> Unit,
  onUnblockMac: (String) -> Unit
) {
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
        Column {
          Text("Panel de Control y Correlación de MACs", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 13.sp)
          Text("Bloqueo en cascada y auditoría de navegación permisiva", fontSize = 11.sp, color = TextSecondary)
        }
        Icon(Icons.Default.AdminPanelSettings, contentDescription = null, tint = WarningAmber)
      }
    }

    Spacer(modifier = Modifier.height(10.dp))

    if (sessions.isEmpty()) {
      Box(modifier = Modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
        Text("No hay sesiones monitoreadas en la base de datos.", color = TextMuted, fontSize = 12.sp)
      }
    } else {
      LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        contentPadding = PaddingValues(bottom = 24.dp)
      ) {
        items(sessions, key = { it.id }) { session ->
          SessionItemCard(
            session = session,
            onBlock = { onBlockMac(session.macAddress) },
            onUnblock = { onUnblockMac(session.macAddress) }
          )
        }
      }
    }
  }
}

@Composable
fun SessionItemCard(
  session: MonitoredSessionEntity,
  onBlock: () -> Unit,
  onUnblock: () -> Unit
) {
  val isBlocked = session.isMacBlocked || session.currentStatus == "Blocked"
  val isAlerted = session.currentStatus == "Alerted"

  val (borderColor, statusBadgeBg, statusBadgeColor) = when {
    isBlocked -> Triple(AlertRed, RedGlow, AlertRed)
    isAlerted -> Triple(WarningAmber, Color(0x33FFCC00), WarningAmber)
    else -> Triple(CyberGreen, GreenGlow, CyberGreen)
  }

  Card(
    modifier = Modifier.fillMaxWidth().testTag("session_card_${session.macAddress}"),
    shape = RoundedCornerShape(10.dp),
    colors = CardDefaults.cardColors(containerColor = DarkSurface),
    border = androidx.compose.foundation.BorderStroke(1.dp, borderColor.copy(alpha = 0.5f))
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
              text = if (isBlocked) "BLOQUEADO" else if (isAlerted) "MONITOREADO" else "NOMINAL",
              color = statusBadgeColor,
              fontSize = 9.sp,
              fontWeight = FontWeight.Bold,
              modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
            )
          }
          Text(session.ipAddress, fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 13.sp, fontFamily = FontFamily.Monospace)
        }

        if (isBlocked) {
          OutlinedButton(
            onClick = onUnblock,
            modifier = Modifier.height(28.dp),
            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberCyan),
            border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan)
          ) {
            Text("Desbloquear", fontSize = 10.sp, fontWeight = FontWeight.Bold)
          }
        } else {
          Button(
            onClick = onBlock,
            modifier = Modifier.height(28.dp),
            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
            colors = ButtonDefaults.buttonColors(containerColor = AlertRed, contentColor = Color.White)
          ) {
            Text("Bloquear en Cascada", fontSize = 10.sp, fontWeight = FontWeight.Bold)
          }
        }
      }

      Spacer(modifier = Modifier.height(6.dp))
      Text("Dirección MAC: ${session.macAddress}", fontSize = 11.sp, color = CyberCyan, fontFamily = FontFamily.Monospace)
      
      if (session.emailsUsedCsv.isNotBlank()) {
        Spacer(modifier = Modifier.height(2.dp))
        Text("Correos Asociados: ${session.emailsUsedCsv}", fontSize = 11.sp, color = TextPrimary)
      }

      if (session.failedLoginAttempts > 0) {
        Text("Intentos Fallidos de Login: ${session.failedLoginAttempts} ${if (session.isEmailDisabled) "(Email Deshabilitado)" else ""}", fontSize = 10.sp, color = WarningAmber)
      }

      if (session.visitedUrlsCsv.isNotBlank()) {
        Spacer(modifier = Modifier.height(4.dp))
        Text("Auditoría de Navegación Permisiva (Destinos):", fontSize = 10.sp, color = TextSecondary)
        Text(session.visitedUrlsCsv, fontSize = 10.sp, color = TextPrimary, fontFamily = FontFamily.Monospace)
      }
    }
  }
}
