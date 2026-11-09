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
import androidx.compose.foundation.text.KeyboardOptions
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.local.entity.HoneygateConfigEntity
import com.example.data.repository.AuthResult
import com.example.ui.theme.*

@Composable
fun HoneygateScreen(
  config: HoneygateConfigEntity,
  authResult: AuthResult?,
  redTeamLogs: List<String>,
  escalationLevel: String,
  onSaveConfig: (HoneygateConfigEntity) -> Unit,
  onSubmitAuth: (ip: String, mac: String, email: String, pass: String, otp: String?) -> Unit,
  onSimulateRedTeamCommand: (command: String, canaryUser: String) -> Unit,
  onClearAuthResult: () -> Unit
) {
  var selectedGateMode by remember { mutableIntStateOf(config.gateMode) }

  Column(
    modifier = Modifier
      .fillMaxSize()
      .padding(horizontal = 14.dp, vertical = 8.dp)
  ) {
    // Selector de las 3 Opciones de Puerta de Miel / Honeygate
    Card(
      modifier = Modifier.fillMaxWidth(),
      shape = RoundedCornerShape(12.dp),
      colors = CardDefaults.cardColors(containerColor = DarkSurface),
      border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
    ) {
      Column(modifier = Modifier.padding(10.dp)) {
        Text("Modo Operativo de Puerta de Miel (Honeygate)", fontSize = 11.sp, color = TextSecondary)
        Spacer(modifier = Modifier.height(8.dp))
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
          GateModeButton(
            mode = 1,
            title = "Opción 1: Portal Auth",
            isSelected = selectedGateMode == 1,
            onClick = {
              selectedGateMode = 1
              onSaveConfig(config.copy(gateMode = 1))
            },
            modifier = Modifier.weight(1f)
          )
          GateModeButton(
            mode = 2,
            title = "Opción 2: Red Team",
            isSelected = selectedGateMode == 2,
            onClick = {
              selectedGateMode = 2
              onSaveConfig(config.copy(gateMode = 2))
            },
            modifier = Modifier.weight(1f)
          )
          GateModeButton(
            mode = 3,
            title = "Opción 3: Proxy Unificado",
            isSelected = selectedGateMode == 3,
            onClick = {
              selectedGateMode = 3
              onSaveConfig(config.copy(gateMode = 3))
            },
            modifier = Modifier.weight(1f)
          )
        }
      }
    }

    Spacer(modifier = Modifier.height(10.dp))

    // Contenido dinámico según el modo seleccionado
    when (selectedGateMode) {
      1 -> Option1CorporateAuthGate(
        config = config,
        authResult = authResult,
        onSaveConfig = onSaveConfig,
        onSubmitAuth = onSubmitAuth,
        onClearAuthResult = onClearAuthResult
      )
      2 -> Option2RedTeamHoneygate(
        config = config,
        redTeamLogs = redTeamLogs,
        escalationLevel = escalationLevel,
        onSaveConfig = onSaveConfig,
        onRunCommand = onSimulateRedTeamCommand
      )
      3 -> Option3UnifiedProxyGate(
        config = config,
        onSaveConfig = onSaveConfig
      )
    }
  }
}

@Composable
fun GateModeButton(
  mode: Int,
  title: String,
  isSelected: Boolean,
  onClick: () -> Unit,
  modifier: Modifier = Modifier
) {
  val (color, bg) = when (mode) {
    1 -> CyberGreen to GreenGlow
    2 -> AlertRed to RedGlow
    else -> CyberCyan to CyanGlow
  }

  Surface(
    modifier = modifier
      .clickable(onClick = onClick)
      .testTag("honeygate_mode_$mode"),
    shape = RoundedCornerShape(8.dp),
    color = if (isSelected) bg else DarkSurfaceVariant,
    border = androidx.compose.foundation.BorderStroke(1.dp, if (isSelected) color else DarkBorder)
  ) {
    Box(
      modifier = Modifier.padding(vertical = 8.dp, horizontal = 4.dp),
      contentAlignment = Alignment.Center
    ) {
      Text(
        text = title,
        color = if (isSelected) color else TextSecondary,
        fontSize = 11.sp,
        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
        maxLines = 1
      )
    }
  }
}

// =============================================================================
// OPCIÓN 1: PORTAL DE AUTENTICACIÓN CORPORATIVO Y DECEPCIÓN
// =============================================================================
@Composable
fun Option1CorporateAuthGate(
  config: HoneygateConfigEntity,
  authResult: AuthResult?,
  onSaveConfig: (HoneygateConfigEntity) -> Unit,
  onSubmitAuth: (String, String, String, String, String?) -> Unit,
  onClearAuthResult: () -> Unit
) {
  var companyName by remember { mutableStateOf(config.companyName) }
  var capturedIp by remember { mutableStateOf("192.168.1.105") }
  var capturedMac by remember { mutableStateOf("52:54:00:12:34:56") }
  var emailInput by remember { mutableStateOf("") }
  var passInput by remember { mutableStateOf("") }
  var otpInput by remember { mutableStateOf("") }
  var otpSent by remember { mutableStateOf(false) }

  LazyColumn(
    modifier = Modifier.fillMaxSize(),
    verticalArrangement = Arrangement.spacedBy(12.dp),
    contentPadding = PaddingValues(bottom = 24.dp)
  ) {
    // 1. Personalizador de Marca y Diseño
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
      ) {
        Column(modifier = Modifier.padding(12.dp)) {
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Text("Diseño y Marca del Portal Corporativo", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 12.sp)
            Icon(Icons.Default.Palette, contentDescription = null, tint = CyberGreen, modifier = Modifier.size(16.dp))
          }
          Spacer(modifier = Modifier.height(8.dp))
          OutlinedTextField(
            value = companyName,
            onValueChange = {
              companyName = it
              onSaveConfig(config.copy(companyName = it))
            },
            label = { Text("Nombre de la Empresa", fontSize = 11.sp) },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            textStyle = androidx.compose.ui.text.TextStyle(fontSize = 12.sp, color = TextPrimary),
            colors = OutlinedTextFieldDefaults.colors(
              focusedContainerColor = DarkSurfaceVariant,
              unfocusedContainerColor = DarkSurfaceVariant,
              focusedBorderColor = CyberGreen,
              unfocusedBorderColor = DarkBorder
            )
          )
        }
      }
    }

    // 2. Telemetría Previa de Red Capturada
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF0C131D)),
        border = androidx.compose.foundation.BorderStroke(1.dp, CyanGlow)
      ) {
        Column(modifier = Modifier.padding(12.dp)) {
          Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Icon(Icons.Default.Sensors, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(16.dp))
            Text("Parámetros de Red Capturados Antes del Registro", fontWeight = FontWeight.Bold, color = CyberCyan, fontSize = 12.sp)
          }
          Spacer(modifier = Modifier.height(6.dp))
          Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            OutlinedTextField(
              value = capturedIp,
              onValueChange = { capturedIp = it },
              label = { Text("IP de Origen", fontSize = 10.sp) },
              modifier = Modifier.weight(1f),
              singleLine = true,
              textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
            )
            OutlinedTextField(
              value = capturedMac,
              onValueChange = { capturedMac = it },
              label = { Text("MAC Address", fontSize = 10.sp) },
              modifier = Modifier.weight(1.2f),
              singleLine = true,
              textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
            )
          }
        }
      }
    }

    // 3. Formulario Interactivo del Portal Honeygate
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
      ) {
        Column(modifier = Modifier.padding(14.dp)) {
          Text(companyName, fontWeight = FontWeight.Bold, color = CyberGreen, fontSize = 15.sp)
          Text("Portal de Autenticación & Registro Corporativo", fontSize = 11.sp, color = TextSecondary)
          Spacer(modifier = Modifier.height(12.dp))

          OutlinedTextField(
            value = emailInput,
            onValueChange = { emailInput = it },
            label = { Text("Correo Electrónico Corporativo", fontSize = 11.sp) },
            modifier = Modifier.fillMaxWidth().testTag("honeygate_email_input"),
            singleLine = true,
            textStyle = androidx.compose.ui.text.TextStyle(fontSize = 12.sp, color = TextPrimary)
          )
          Spacer(modifier = Modifier.height(8.dp))

          OutlinedTextField(
            value = passInput,
            onValueChange = { passInput = it },
            label = { Text("Contraseña de Acceso", fontSize = 11.sp) },
            modifier = Modifier.fillMaxWidth().testTag("honeygate_password_input"),
            singleLine = true,
            textStyle = androidx.compose.ui.text.TextStyle(fontSize = 12.sp, color = TextPrimary)
          )

          if (otpSent) {
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
              value = otpInput,
              onValueChange = { otpInput = it },
              label = { Text("Código Numérico OTP enviado a su mail (ej: 948210)", fontSize = 11.sp) },
              modifier = Modifier.fillMaxWidth().testTag("honeygate_otp_input"),
              singleLine = true,
              keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
              textStyle = androidx.compose.ui.text.TextStyle(fontSize = 13.sp, fontFamily = FontFamily.Monospace, color = CyberGreen)
            )
          }

          Spacer(modifier = Modifier.height(12.dp))

          Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
              onClick = {
                otpSent = true
                otpInput = "948210"
              },
              modifier = Modifier.weight(1f).height(38.dp)
            ) {
              Text("Enviar OTP", fontSize = 11.sp)
            }

            Button(
              onClick = {
                onSubmitAuth(capturedIp, capturedMac, emailInput, passInput, if (otpSent) otpInput else null)
              },
              colors = ButtonDefaults.buttonColors(containerColor = CyberGreen, contentColor = Color.Black),
              modifier = Modifier.weight(1f).height(38.dp).testTag("honeygate_submit_button")
            ) {
              Text("Ingresar", fontWeight = FontWeight.Bold, fontSize = 12.sp)
            }
          }

          // Banner de Resultado de la Evaluación Forense
          authResult?.let { res ->
            Spacer(modifier = Modifier.height(12.dp))
            val (resBg, resColor) = when (res.status) {
              "Blocked" -> RedGlow to AlertRed
              "Alerted" -> Color(0x33FFCC00) to WarningAmber
              else -> GreenGlow to CyberGreen
            }

            Surface(
              shape = RoundedCornerShape(8.dp),
              color = resBg,
              border = androidx.compose.foundation.BorderStroke(1.dp, resColor),
              modifier = Modifier.fillMaxWidth()
            ) {
              Column(modifier = Modifier.padding(10.dp)) {
                Row(
                  modifier = Modifier.fillMaxWidth(),
                  horizontalArrangement = Arrangement.SpaceBetween,
                  verticalAlignment = Alignment.CenterVertically
                ) {
                  Text("Resultado del Monitoreo: ${res.status.uppercase()}", fontWeight = FontWeight.Bold, color = resColor, fontSize = 12.sp)
                  IconButton(onClick = onClearAuthResult, modifier = Modifier.size(20.dp)) {
                    Icon(Icons.Default.Close, contentDescription = null, tint = resColor, modifier = Modifier.size(14.dp))
                  }
                }
                Spacer(modifier = Modifier.height(4.dp))
                Text(res.message, fontSize = 11.sp, color = TextPrimary)
                if (res.shouldAllowNavigation) {
                  Spacer(modifier = Modifier.height(4.dp))
                  Text("Navegación Permitida: La sesión continúa abierta mientras se registran las URLs visitadas.", fontSize = 10.sp, color = CyberCyan)
                }
              }
            }
          }
        }
      }
    }

    // 4. Inyectores de Ataques y Simulaciones Defensivas Rápida
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
      ) {
        Column(modifier = Modifier.padding(12.dp)) {
          Text("Simuladores de Vectores de Ataque para Auditoría", fontWeight = FontWeight.Bold, color = WarningAmber, fontSize = 12.sp)
          Spacer(modifier = Modifier.height(8.dp))

          Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Button(
              onClick = {
                emailInput = "admin@corp.com"
                passInput = "' OR '1'='1' --"
                onSubmitAuth(capturedIp, capturedMac, emailInput, passInput, null)
              },
              colors = ButtonDefaults.buttonColors(containerColor = AlertRed),
              modifier = Modifier.weight(1f).height(36.dp).testTag("sim_sqli_button")
            ) {
              Text("Inyectar SQLi", fontSize = 10.sp, fontWeight = FontWeight.Bold)
            }

            Button(
              onClick = {
                emailInput = "usuario_${System.currentTimeMillis() % 1000}@aerosec.corp"
                passInput = "Secret2026!"
                onSubmitAuth(capturedIp, capturedMac, emailInput, passInput, "948210")
              },
              colors = ButtonDefaults.buttonColors(containerColor = WarningAmber, contentColor = Color.Black),
              modifier = Modifier.weight(1f).height(36.dp).testTag("sim_multi_mac_button")
            ) {
              Text("Multi-User MAC", fontSize = 10.sp, fontWeight = FontWeight.Bold)
            }
          }

          Spacer(modifier = Modifier.height(6.dp))

          Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            OutlinedButton(
              onClick = {
                emailInput = "victima_lock@aerosec.corp"
                passInput = "clave_invalida_123"
                onSubmitAuth(capturedIp, capturedMac, emailInput, passInput, null)
              },
              modifier = Modifier.weight(1f).height(36.dp)
            ) {
              Text("3 Intentos Fallidos", fontSize = 10.sp)
            }

            OutlinedButton(
              onClick = {
                emailInput = "jmartinez@aerosec.corp"
                passInput = "CorpSecure2026!"
                otpInput = "948210"
                otpSent = true
                onSubmitAuth(capturedIp, capturedMac, emailInput, passInput, "948210")
              },
              modifier = Modifier.weight(1f).height(36.dp)
            ) {
              Text("Acceso Válido", fontSize = 10.sp, color = CyberGreen)
            }
          }
        }
      }
    }
  }
}

// =============================================================================
// OPCIÓN 2: PUERTA DE MIEL PARA EJERCICIOS DE RED TEAM
// =============================================================================
@Composable
fun Option2RedTeamHoneygate(
  config: HoneygateConfigEntity,
  redTeamLogs: List<String>,
  escalationLevel: String,
  onSaveConfig: (HoneygateConfigEntity) -> Unit,
  onRunCommand: (String, String) -> Unit
) {
  var compromisedAreas by remember { mutableStateOf(config.compromisedAreas) }
  var canaryUsers by remember { mutableStateOf(config.canaryUsersCsv) }
  var commandInput by remember { mutableStateOf("") }
  val activeCanaryUser = canaryUsers.split(",").firstOrNull()?.trim() ?: "admin_sec@aerosec.corp"

  LazyColumn(
    modifier = Modifier.fillMaxSize(),
    verticalArrangement = Arrangement.spacedBy(12.dp),
    contentPadding = PaddingValues(bottom = 24.dp)
  ) {
    // 1. Configuración de Áreas Comprometidas y Canary Users
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, AlertRed.copy(alpha = 0.5f))
      ) {
        Column(modifier = Modifier.padding(12.dp)) {
          Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Icon(Icons.Default.SecurityUpdateWarning, contentDescription = null, tint = AlertRed, modifier = Modifier.size(16.dp))
            Text("Parámetros del Ejercicio de Red Team", fontWeight = FontWeight.Bold, color = AlertRed, fontSize = 12.sp)
          }
          Spacer(modifier = Modifier.height(6.dp))
          OutlinedTextField(
            value = compromisedAreas,
            onValueChange = {
              compromisedAreas = it
              onSaveConfig(config.copy(compromisedAreas = it))
            },
            label = { Text("1 a 2 Áreas Comprometidas", fontSize = 10.sp) },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp, color = TextPrimary)
          )
          Spacer(modifier = Modifier.height(6.dp))
          OutlinedTextField(
            value = canaryUsers,
            onValueChange = {
              canaryUsers = it
              onSaveConfig(config.copy(canaryUsersCsv = it))
            },
            label = { Text("1 a 3 Canary Users Comprometidos", fontSize = 10.sp) },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = WarningAmber)
          )
        }
      }
    }

    // 2. Indicador de Nivel de Escalación de Privilegios
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF140D17)),
        border = androidx.compose.foundation.BorderStroke(1.dp, AlertRed)
      ) {
        Row(
          modifier = Modifier.padding(12.dp).fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically
        ) {
          Column {
            Text("Nivel de Escalación Red Team:", fontSize = 11.sp, color = TextSecondary)
            Text(escalationLevel, fontWeight = FontWeight.Bold, color = AlertRed, fontSize = 13.sp)
          }
          Icon(Icons.Default.TrendingUp, contentDescription = null, tint = AlertRed)
        }
      }
    }

    // 3. Emulación de Servicios en Segundo Plano (Apache, MySQL, SSH)
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
      ) {
        Column(modifier = Modifier.padding(12.dp)) {
          Text("Servicios Señuelo Emulados en Segundo Plano", fontWeight = FontWeight.Bold, color = CyberCyan, fontSize = 12.sp)
          Spacer(modifier = Modifier.height(8.dp))
          Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ServiceBadge("MySQL DB (3306)", true, Modifier.weight(1f))
            ServiceBadge("Apache Web (8080)", true, Modifier.weight(1f))
            ServiceBadge("SSH Honey (2222)", true, Modifier.weight(1f))
          }
        }
      }
    }

    // 4. Consola Interactiva del Red Team con Registro de Comandos
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF070B10)),
        border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
      ) {
        Column(modifier = Modifier.padding(12.dp)) {
          Text("Consola del Red Team (Monitoreo de Tipeo en Vivo)", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 12.sp)
          Spacer(modifier = Modifier.height(6.dp))
          
          Box(
            modifier = Modifier
              .fillMaxWidth()
              .height(130.dp)
              .clip(RoundedCornerShape(6.dp))
              .background(Color.Black)
              .padding(8.dp)
          ) {
            LazyColumn(modifier = Modifier.fillMaxSize()) {
              items(redTeamLogs) { line ->
                Text(
                  text = line,
                  color = if (line.contains("!")) AlertRed else CyberGreen,
                  fontSize = 11.sp,
                  fontFamily = FontFamily.Monospace
                )
              }
            }
          }

          Spacer(modifier = Modifier.height(8.dp))

          Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            OutlinedTextField(
              value = commandInput,
              onValueChange = { commandInput = it },
              placeholder = { Text("Ej: sudo -l, cat /etc/shadow, netstat", fontSize = 11.sp, color = TextMuted) },
              modifier = Modifier.weight(1f),
              singleLine = true,
              textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = CyberGreen)
            )

            Button(
              onClick = {
                if (commandInput.isNotBlank()) {
                  onRunCommand(commandInput, activeCanaryUser)
                  commandInput = ""
                }
              },
              colors = ButtonDefaults.buttonColors(containerColor = AlertRed),
              modifier = Modifier.height(48.dp)
            ) {
              Text("Ejecutar", fontSize = 11.sp, fontWeight = FontWeight.Bold)
            }
          }

          Spacer(modifier = Modifier.height(6.dp))

          // Botones de simulación rápida de explotación
          Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            SuggestionChip(
              onClick = { onRunCommand("sudo -l", activeCanaryUser) },
              label = { Text("sudo -l", fontSize = 10.sp) }
            )
            SuggestionChip(
              onClick = { onRunCommand("cat /etc/shadow", activeCanaryUser) },
              label = { Text("/etc/shadow (Honeytokens)", fontSize = 10.sp, color = AlertRed) }
            )
            SuggestionChip(
              onClick = { onRunCommand("netstat -antp", activeCanaryUser) },
              label = { Text("netstat -antp", fontSize = 10.sp) }
            )
          }
        }
      }
    }
  }
}

@Composable
fun ServiceBadge(name: String, active: Boolean, modifier: Modifier = Modifier) {
  Surface(
    shape = RoundedCornerShape(6.dp),
    color = if (active) GreenGlow else DarkSurfaceVariant,
    border = androidx.compose.foundation.BorderStroke(1.dp, if (active) CyberGreen else DarkBorder),
    modifier = modifier
  ) {
    Box(modifier = Modifier.padding(6.dp), contentAlignment = Alignment.Center) {
      Text(name, fontSize = 10.sp, color = if (active) CyberGreen else TextMuted, fontWeight = FontWeight.SemiBold)
    }
  }
}

// =============================================================================
// OPCIÓN 3: ESCENARIO UNIFICADO / PROXY DECEPTIVO DE NAVEGACIÓN
// =============================================================================
@Composable
fun Option3UnifiedProxyGate(
  config: HoneygateConfigEntity,
  onSaveConfig: (HoneygateConfigEntity) -> Unit
) {
  var proxyEnabled by remember { mutableStateOf(config.transparentProxyEnabled) }

  LazyColumn(
    modifier = Modifier.fillMaxSize(),
    verticalArrangement = Arrangement.spacedBy(12.dp),
    contentPadding = PaddingValues(bottom = 24.dp)
  ) {
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan.copy(alpha = 0.5f))
      ) {
        Column(modifier = Modifier.padding(12.dp)) {
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Column {
              Text("Proxy Deceptivo Transparente", fontWeight = FontWeight.Bold, color = CyberCyan, fontSize = 13.sp)
              Text("Permite navegación hacia Internet mientras audita URLs y MACs", fontSize = 11.sp, color = TextSecondary)
            }
            Switch(
              checked = proxyEnabled,
              onCheckedChange = {
                proxyEnabled = it
                onSaveConfig(config.copy(transparentProxyEnabled = it))
              },
              colors = SwitchDefaults.colors(checkedThumbColor = CyberCyan, checkedTrackColor = CyanGlow)
            )
          }
        }
      }
    }

    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
      ) {
        Column(modifier = Modifier.padding(12.dp)) {
          Text("Registro de Conexiones en Tiempo Real (Proxy Audit)", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 12.sp)
          Spacer(modifier = Modifier.height(8.dp))

          val proxyTraffic = listOf(
            Triple("192.168.1.105", "52:54:00:12:34:56", "GET https://api.threat-intel.org/c2/checkin"),
            Triple("172.16.4.88", "00:1a:2b:3c:4d:5e", "DNS query -> exfil.attacker-domain.xyz"),
            Triple("10.0.2.15", "00:50:56:c0:00:08", "GET https://corporate.aerosec.corp/dashboard")
          )

          proxyTraffic.forEach { (ip, mac, target) ->
            Surface(
              shape = RoundedCornerShape(6.dp),
              color = DarkSurfaceVariant,
              modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
            ) {
              Column(modifier = Modifier.padding(8.dp)) {
                Row(
                  modifier = Modifier.fillMaxWidth(),
                  horizontalArrangement = Arrangement.SpaceBetween
                ) {
                  Text("IP: $ip", fontSize = 10.sp, color = CyberCyan, fontFamily = FontFamily.Monospace)
                  Text("MAC: $mac", fontSize = 10.sp, color = TextMuted, fontFamily = FontFamily.Monospace)
                }
                Spacer(modifier = Modifier.height(2.dp))
                Text(target, fontSize = 11.sp, color = if (target.contains("exfil") || target.contains("c2")) AlertRed else TextPrimary, fontFamily = FontFamily.Monospace)
              }
            }
          }
        }
      }
    }
  }
}
