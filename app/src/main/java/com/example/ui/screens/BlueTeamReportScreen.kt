package com.example.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Description
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
  reportText: String
) {
  val context = LocalContext.current

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
      Row(
        modifier = Modifier.padding(12.dp).fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Column(modifier = Modifier.weight(1f)) {
          Text("Informe de Ingeniería para Blue Team", fontWeight = FontWeight.Bold, color = CyberCyan, fontSize = 13.sp)
          Text("Matriz MITRE ATT&CK, Correlación Forense y Recomendaciones", fontSize = 11.sp, color = TextSecondary)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
          Button(
            onClick = {
              val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
              val clip = ClipData.newPlainText("Informe Blue Team HoneyGate", reportText)
              clipboard.setPrimaryClip(clip)
              Toast.makeText(context, "Informe copiado al portapapeles", Toast.LENGTH_SHORT).show()
            },
            colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black),
            modifier = Modifier.testTag("copy_report_button")
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
                putExtra(android.content.Intent.EXTRA_SUBJECT, "HoneyGate - Informe Forense Blue Team")
                type = "text/plain"
              }
              val shareIntent = android.content.Intent.createChooser(sendIntent, "Compartir Informe Forense")
              context.startActivity(shareIntent)
            },
            colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberCyan),
            border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan.copy(alpha = 0.6f)),
            modifier = Modifier.testTag("share_report_button")
          ) {
            Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(4.dp))
            Text("Compartir", fontSize = 11.sp, fontWeight = FontWeight.Bold)
          }
        }
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
            lineHeight = 15.sp
          )
        }
      }
    }
  }
}
