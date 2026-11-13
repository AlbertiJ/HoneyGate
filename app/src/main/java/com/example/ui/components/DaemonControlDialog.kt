package com.example.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.example.data.local.entity.HoneygateConfigEntity
import com.example.data.remote.DaemonStatus
import com.example.ui.theme.*

@Composable
fun DaemonStatusBadge(
  daemonStatus: DaemonStatus?,
  isSyncing: Boolean,
  onClick: () -> Unit,
  modifier: Modifier = Modifier
) {
  val isOnline = daemonStatus?.online == true
  val badgeBg = if (isOnline) GreenGlow else RedGlow
  val badgeBorder = if (isOnline) CyberGreen else AlertRed
  val textColor = if (isOnline) CyberGreen else AlertRed

  Surface(
    shape = RoundedCornerShape(16.dp),
    color = badgeBg,
    border = androidx.compose.foundation.BorderStroke(1.dp, badgeBorder),
    modifier = modifier
      .clip(RoundedCornerShape(16.dp))
      .clickable(onClick = onClick)
      .testTag("daemon_status_badge")
  ) {
    Row(
      modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
      verticalAlignment = Alignment.CenterVertically,
      horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
      if (isSyncing) {
        CircularProgressIndicator(
          modifier = Modifier.size(10.dp),
          color = CyberCyan,
          strokeWidth = 2.dp
        )
      } else {
        Box(
          modifier = Modifier
            .size(8.dp)
            .clip(CircleShape)
            .background(if (isOnline) CyberGreen else AlertRed)
        )
      }

      Text(
        text = if (isOnline) "Daemon: ${daemonStatus?.latencyMs ?: 0}ms" else "Daemon: Offline",
        fontSize = 10.sp,
        color = textColor,
        fontWeight = FontWeight.SemiBold
      )
    }
  }
}

@Composable
fun DaemonControlDialog(
  config: HoneygateConfigEntity,
  daemonStatus: DaemonStatus?,
  isSyncing: Boolean,
  syncMessage: String?,
  onDismiss: () -> Unit,
  onCheckHealth: () -> Unit,
  onSyncData: () -> Unit,
  onUpdateConfig: (baseUrl: String, token: String, enabled: Boolean) -> Unit,
  onClearSyncMessage: () -> Unit
) {
  var baseUrlInput by remember(config.daemonBaseUrl) { mutableStateOf(config.daemonBaseUrl) }
  var tokenInput by remember(config.daemonAuthToken) { mutableStateOf(config.daemonAuthToken) }
  var syncEnabled by remember(config.daemonSyncEnabled) { mutableStateOf(config.daemonSyncEnabled) }
  var showToken by remember { mutableStateOf(false) }

  Dialog(onDismissRequest = onDismiss) {
    Surface(
      shape = RoundedCornerShape(16.dp),
      color = DarkSurface,
      border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder),
      modifier = Modifier
        .fillMaxWidth()
        .padding(4.dp)
        .testTag("daemon_control_dialog")
    ) {
      Column(
        modifier = Modifier
          .fillMaxWidth()
          .padding(16.dp)
      ) {
        // Encabezado
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically
        ) {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
          ) {
            Icon(
              imageVector = Icons.Default.Terminal,
              contentDescription = "Daemon Linux",
              tint = CyberCyan,
              modifier = Modifier.size(22.dp)
            )
            Column {
              Text(
                text = "Módulo 1: Conector Daemon Linux",
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
                color = TextPrimary
              )
              Text(
                text = "Control Perimetral Remoto en Tiempo Real",
                fontSize = 10.sp,
                color = TextSecondary
              )
            }
          }
          IconButton(
            onClick = onDismiss,
            modifier = Modifier.size(28.dp)
          ) {
            Icon(Icons.Default.Close, contentDescription = "Cerrar", tint = TextMuted)
          }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Indicador de Estado del Daemon
        val isOnline = daemonStatus?.online == true
        Surface(
          shape = RoundedCornerShape(10.dp),
          color = if (isOnline) GreenGlow else RedGlow,
          border = androidx.compose.foundation.BorderStroke(1.dp, if (isOnline) CyberGreen else AlertRed),
          modifier = Modifier.fillMaxWidth()
        ) {
          Column(modifier = Modifier.padding(10.dp)) {
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.SpaceBetween,
              verticalAlignment = Alignment.CenterVertically
            ) {
              Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
              ) {
                Box(
                  modifier = Modifier
                    .size(10.dp)
                    .clip(CircleShape)
                    .background(if (isOnline) CyberGreen else AlertRed)
                )
                Text(
                  text = if (isOnline) "DAEMON ACTIVO EN KERNEL LINUX" else "DAEMON DESCONECTADO",
                  fontSize = 11.sp,
                  fontWeight = FontWeight.Bold,
                  color = if (isOnline) CyberGreen else AlertRed
                )
              }
              if (isOnline) {
                Text(
                  text = "${daemonStatus?.latencyMs} ms",
                  fontSize = 11.sp,
                  fontFamily = FontFamily.Monospace,
                  color = CyberGreen
                )
              }
            }

            if (!isOnline && daemonStatus?.errorMessage != null) {
              Spacer(modifier = Modifier.height(4.dp))
              Text(
                text = daemonStatus.errorMessage,
                fontSize = 10.sp,
                color = AlertRed
              )
            }

            if (isOnline && daemonStatus != null) {
              Spacer(modifier = Modifier.height(8.dp))
              Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
              ) {
                DaemonMetricItem("Sockets Activos", "${daemonStatus.activeConnections}")
                DaemonMetricItem("Total Conexiones", "${daemonStatus.totalConnections}")
                DaemonMetricItem("IPs Aisladas", "${daemonStatus.isolatedCount}")
                DaemonMetricItem("Violaciones Rate", "${daemonStatus.rateLimitViolations}")
              }
            }
          }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Campos de Configuración
        Text("Endpoint del Motor (Python / Kali / Host):", fontSize = 11.sp, color = TextSecondary)
        Spacer(modifier = Modifier.height(4.dp))
        OutlinedTextField(
          value = baseUrlInput,
          onValueChange = { baseUrlInput = it },
          placeholder = { Text("http://10.0.2.2:8888 o http://192.168.1.X:8888", fontSize = 11.sp) },
          singleLine = true,
          modifier = Modifier
            .fillMaxWidth()
            .testTag("daemon_url_input"),
          textStyle = LocalTextStyle.current.copy(fontSize = 12.sp, fontFamily = FontFamily.Monospace),
          colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = CyberCyan,
            unfocusedBorderColor = DarkBorder,
            focusedTextColor = TextPrimary,
            unfocusedTextColor = TextPrimary
          )
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text("Token de Autenticación (X-Auth-Token):", fontSize = 11.sp, color = TextSecondary)
        Spacer(modifier = Modifier.height(4.dp))
        OutlinedTextField(
          value = tokenInput,
          onValueChange = { tokenInput = it },
          placeholder = { Text("Token configurado en daemon", fontSize = 11.sp) },
          singleLine = true,
          visualTransformation = if (showToken) VisualTransformation.None else PasswordVisualTransformation(),
          trailingIcon = {
            IconButton(onClick = { showToken = !showToken }) {
              Icon(
                if (showToken) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                contentDescription = "Toggle token",
                tint = TextMuted,
                modifier = Modifier.size(18.dp)
              )
            }
          },
          modifier = Modifier
            .fillMaxWidth()
            .testTag("daemon_token_input"),
          textStyle = LocalTextStyle.current.copy(fontSize = 12.sp, fontFamily = FontFamily.Monospace),
          colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = CyberCyan,
            unfocusedBorderColor = DarkBorder,
            focusedTextColor = TextPrimary,
            unfocusedTextColor = TextPrimary
          )
        )

        Spacer(modifier = Modifier.height(8.dp))

        // Toggle Sync
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically
        ) {
          Column {
            Text("Sincronización Perimetral Activa", fontSize = 11.sp, color = TextPrimary)
            Text("Envía órdenes de kernel shutdown en bloqueos", fontSize = 9.sp, color = TextMuted)
          }
          Switch(
            checked = syncEnabled,
            onCheckedChange = { syncEnabled = it },
            colors = SwitchDefaults.colors(
              checkedThumbColor = CyberGreen,
              checkedTrackColor = GreenGlow,
              uncheckedThumbColor = TextMuted,
              uncheckedTrackColor = DarkSurface
            )
          )
        }

        // Mensaje de resultado de Sync
        AnimatedVisibility(visible = syncMessage != null) {
          syncMessage?.let { msg ->
            Surface(
              shape = RoundedCornerShape(8.dp),
              color = CyanGlow,
              border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan),
              modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 6.dp)
            ) {
              Row(
                modifier = Modifier.padding(8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
              ) {
                Text(msg, fontSize = 10.sp, color = CyberCyan, modifier = Modifier.weight(1f))
                IconButton(onClick = onClearSyncMessage, modifier = Modifier.size(20.dp)) {
                  Icon(Icons.Default.Close, contentDescription = "Dismiss", tint = CyberCyan, modifier = Modifier.size(14.dp))
                }
              }
            }
          }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Botones de Acción
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
          OutlinedButton(
            onClick = onCheckHealth,
            modifier = Modifier
              .weight(1f)
              .testTag("daemon_test_health_button"),
            shape = RoundedCornerShape(8.dp),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberCyan),
            border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan)
          ) {
            Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(14.dp))
            Spacer(modifier = Modifier.width(4.dp))
            Text("Probar", fontSize = 11.sp)
          }

          Button(
            onClick = onSyncData,
            enabled = !isSyncing,
            modifier = Modifier
              .weight(1.3f)
              .testTag("daemon_sync_button"),
            shape = RoundedCornerShape(8.dp),
            colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black)
          ) {
            if (isSyncing) {
              CircularProgressIndicator(modifier = Modifier.size(14.dp), color = Color.Black, strokeWidth = 2.dp)
            } else {
              Icon(Icons.Default.Sync, contentDescription = null, modifier = Modifier.size(14.dp))
            }
            Spacer(modifier = Modifier.width(4.dp))
            Text("Sincronizar", fontSize = 11.sp, fontWeight = FontWeight.Bold)
          }

          Button(
            onClick = {
              onUpdateConfig(baseUrlInput, tokenInput, syncEnabled)
            },
            modifier = Modifier
              .weight(1.2f)
              .testTag("daemon_save_config_button"),
            shape = RoundedCornerShape(8.dp),
            colors = ButtonDefaults.buttonColors(containerColor = CyberGreen, contentColor = Color.Black)
          ) {
            Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(14.dp))
            Spacer(modifier = Modifier.width(4.dp))
            Text("Guardar", fontSize = 11.sp, fontWeight = FontWeight.Bold)
          }
        }
      }
    }
  }
}

@Composable
private fun DaemonMetricItem(label: String, value: String) {
  Column(horizontalAlignment = Alignment.CenterHorizontally) {
    Text(text = value, fontSize = 13.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace, color = TextPrimary)
    Text(text = label, fontSize = 8.sp, color = TextSecondary)
  }
}
