package com.example.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.theme.*

@Composable
fun BlueTeamReportScreen(
  reportText: String,
  selectedFormat: String,
  includeFullEmail: Boolean,
  isLoading: Boolean,
  errorMessage: String?,
  isOnline: Boolean,
  onSelectFormat: (String) -> Unit,
  onToggleIncludeFullEmail: (Boolean) -> Unit,
  onRefreshReport: () -> Unit
) {
  val context = LocalContext.current
  val hasContent = reportText.isNotBlank()

  Column(
    modifier = Modifier
      .fillMaxSize()
      .padding(horizontal = 14.dp, vertical = 8.dp)
  ) {
    Card(
      modifier = Modifier.fillMaxWidth(),
      shape = RoundedCornerShape(10.dp),
      colors = CardDefaults.cardColors(containerColor = DarkSurface),
      border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan.copy(alpha = 0.5f))
    ) {
      Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically
        ) {
          Column(modifier = Modifier.weight(1f)) {
            Text(
              "Informe del Daemon (/api/report)",
              fontWeight = FontWeight.Bold,
              color = CyberCyan,
              fontSize = 13.sp
            )
            Text(
              if (isOnline) "Fuente: servidor Python HoneyGate" else "Sin conexión — solicitá al daemon al reconectar",
              fontSize = 10.sp,
              color = TextSecondary
            )
          }

          IconButton(
            onClick = onRefreshReport,
            enabled = !isLoading,
            modifier = Modifier
              .size(48.dp)
              .testTag("refresh_report_button")
          ) {
            Icon(
              Icons.Default.Refresh,
              contentDescription = "Actualizar informe del daemon",
              tint = CyberCyan
            )
          }
        }

        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(6.dp),
          verticalAlignment = Alignment.CenterVertically
        ) {
          listOf(
            "markdown" to "Markdown",
            "json" to "JSON",
            "csv" to "CSV"
          ).forEach { (fmtKey, label) ->
            val selected = selectedFormat == fmtKey
            FilterChip(
              selected = selected,
              onClick = { onSelectFormat(fmtKey) },
              label = { Text(label, fontSize = 10.sp, fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal) },
              modifier = Modifier.testTag("report_format_$fmtKey"),
              colors = FilterChipDefaults.filterChipColors(
                containerColor = DarkSurfaceVariant,
                labelColor = TextSecondary,
                selectedContainerColor = CyanGlow,
                selectedLabelColor = CyberCyan
              ),
              border = FilterChipDefaults.filterChipBorder(
                borderColor = if (selected) CyberCyan else DarkBorder,
                selectedBorderColor = CyberCyan,
                enabled = true,
                selected = selected
              )
            )
          }
        }

        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically
        ) {
          Column(modifier = Modifier.weight(1f)) {
            Text("Incluir correo completo del visitante", fontSize = 11.sp, color = TextPrimary)
            Text(
              if (includeFullEmail) "Parámetro include_full_email=1 activo" else "Por defecto enmascarado (j***@dominio)",
              fontSize = 9.sp,
              color = if (includeFullEmail) WarningAmber else TextMuted
            )
          }
          Switch(
            checked = includeFullEmail,
            onCheckedChange = onToggleIncludeFullEmail,
            modifier = Modifier.testTag("report_include_full_email_switch")
          )
        }

        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
          Button(
            onClick = {
              val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
              val clip = ClipData.newPlainText("Informe HoneyGate", reportText)
              clipboard.setPrimaryClip(clip)
              Toast.makeText(context, "Informe copiado al portapapeles", Toast.LENGTH_SHORT).show()
            },
            enabled = hasContent,
            colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black),
            modifier = Modifier
              .weight(1f)
              .minimumInteractiveComponentSize()
              .testTag("copy_report_button")
          ) {
            Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(4.dp))
            Text("Copiar", fontSize = 11.sp, fontWeight = FontWeight.Bold)
          }

          OutlinedButton(
            onClick = {
              val sendIntent = android.content.Intent().apply {
                action = android.content.Intent.ACTION_SEND
                putExtra(android.content.Intent.EXTRA_TEXT, reportText)
                putExtra(android.content.Intent.EXTRA_SUBJECT, "HoneyGate - Informe Forense ($selectedFormat)")
                type = "text/plain"
              }
              val shareIntent = android.content.Intent.createChooser(sendIntent, "Compartir Informe HoneyGate")
              context.startActivity(shareIntent)
            },
            enabled = hasContent,
            colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberCyan),
            border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan.copy(alpha = 0.6f)),
            modifier = Modifier
              .weight(1f)
              .minimumInteractiveComponentSize()
              .testTag("share_report_button")
          ) {
            Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(4.dp))
            Text("Compartir", fontSize = 11.sp, fontWeight = FontWeight.Bold)
          }
        }
      }
    }

    if (isLoading) {
      Spacer(modifier = Modifier.height(6.dp))
      LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = CyberCyan)
    }

    if (!errorMessage.isNullOrBlank()) {
      Spacer(modifier = Modifier.height(8.dp))
      Surface(
        color = RedGlow,
        border = androidx.compose.foundation.BorderStroke(1.dp, AlertRed.copy(alpha = 0.6f)),
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier.fillMaxWidth()
      ) {
        Text(
          text = errorMessage,
          color = TextPrimary,
          fontSize = 11.sp,
          modifier = Modifier.padding(10.dp)
        )
      }
    }

    Spacer(modifier = Modifier.height(10.dp))

    Card(
      modifier = Modifier
        .fillMaxWidth()
        .weight(1f),
      shape = RoundedCornerShape(10.dp),
      colors = CardDefaults.cardColors(containerColor = Color(0xFF070B10)),
      border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
    ) {
      if (!hasContent) {
        Box(
          modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
          contentAlignment = Alignment.Center
        ) {
          Text(
            text = if (isLoading) {
              "Descargando informe desde GET /api/report..."
            } else {
              "Presioná actualizar para obtener el informe real desde el daemon (/api/report)."
            },
            color = TextMuted,
            fontSize = 11.sp
          )
        }
      } else {
        LazyColumn(
          modifier = Modifier
            .fillMaxSize()
            .padding(12.dp)
        ) {
          item {
            Text(
              text = reportText,
              color = Color(0xFFCBD5E1),
              fontSize = 11.sp,
              fontFamily = FontFamily.Monospace,
              lineHeight = 15.sp,
              modifier = Modifier.testTag("daemon_report_content")
            )
          }
        }
      }
    }
  }
}
