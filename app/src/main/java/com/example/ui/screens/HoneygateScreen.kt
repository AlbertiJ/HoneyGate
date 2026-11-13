package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.local.entity.HoneygateConfigEntity
import com.example.data.remote.DaemonConfigUpdate
import com.example.data.repository.Mode1AuthResult
import com.example.data.repository.Mode2ActionResult
import com.example.data.repository.OtpChallenge
import com.example.ui.theme.*

@Composable
fun HoneygateScreen(
  config: HoneygateConfigEntity,
  isOnline: Boolean,
  mode1Result: Mode1AuthResult?,
  mode2Result: Mode2ActionResult?,
  otpChallenge: OtpChallenge?,
  redTeamLogs: List<String>,
  escalationLevel: String,
  onSelectMode: (Int) -> Unit,
  onPushDaemonConfig: (DaemonConfigUpdate) -> Unit,
  onToggleDemoMode: (Boolean) -> Unit,
  onRegisterDemoMode1: (email: String, ip: String, mac: String) -> Unit,
  onRequestDemoOtp: (email: String, ip: String, mac: String) -> Unit,
  onVerifyDemoOtp: (code: String, ip: String, mac: String) -> Boolean,
  onDismissOtp: () -> Unit,
  onRunDemoRedTeamCommand: (canaryUser: String, command: String) -> Unit,
  onClearMode1Result: () -> Unit,
  onUpdateBranding: (name: String, primary: String, accent: String) -> Unit,
  onOpenDaemonSettings: () -> Unit = {}
) {
  var selectedGateMode by remember(config.gateMode) { mutableIntStateOf(config.gateMode) }

  Column(
    modifier = Modifier
      .fillMaxSize()
      .padding(horizontal = 14.dp, vertical = 8.dp)
  ) {
    // Selector de Modo de Operación -> PUT /api/config
    Card(
      modifier = Modifier.fillMaxWidth(),
      shape = RoundedCornerShape(12.dp),
      colors = CardDefaults.cardColors(containerColor = DarkSurface),
      border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
    ) {
      Column(modifier = Modifier.padding(10.dp)) {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically
        ) {
          Text("Modo Operativo del Daemon (PUT /api/config)", fontSize = 11.sp, color = TextSecondary)
          Text(
            text = if (isOnline) "Sincronizado" else "Sin conexión",
            fontSize = 9.sp,
            color = if (isOnline) CyberGreen else AlertRed,
            fontWeight = FontWeight.Bold
          )
        }
        Spacer(modifier = Modifier.height(6.dp))
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
          GateModeTab(
            mode = 1,
            title = "Modo 1: Portal",
            isSelected = selectedGateMode == 1,
            onClick = {
              selectedGateMode = 1
              onSelectMode(1)
            },
            modifier = Modifier.weight(1f)
          )
          GateModeTab(
            mode = 2,
            title = "Modo 2: Honeypot",
            isSelected = selectedGateMode == 2,
            onClick = {
              selectedGateMode = 2
              onSelectMode(2)
            },
            modifier = Modifier.weight(1f)
          )
          GateModeTab(
            mode = 3,
            title = "Modo 3: Mixto",
            isSelected = selectedGateMode == 3,
            onClick = {
              selectedGateMode = 3
              onSelectMode(3)
            },
            modifier = Modifier.weight(1f)
          )
        }
      }
    }

    Spacer(modifier = Modifier.height(10.dp))

    when (selectedGateMode) {
      1 -> Mode1ControlScreen(
        config = config,
        authResult = mode1Result,
        otpChallenge = otpChallenge,
        onPushDaemonConfig = onPushDaemonConfig,
        onToggleDemoMode = onToggleDemoMode,
        onRegisterDemo = onRegisterDemoMode1,
        onRequestDemoOtp = onRequestDemoOtp,
        onVerifyDemoOtp = onVerifyDemoOtp,
        onDismissOtp = onDismissOtp,
        onClearResult = onClearMode1Result,
        onUpdateBranding = onUpdateBranding
      )
      2 -> Mode2ControlScreen(
        config = config,
        redTeamLogs = redTeamLogs,
        escalationLevel = escalationLevel,
        onPushDaemonConfig = onPushDaemonConfig,
        onToggleDemoMode = onToggleDemoMode,
        onRunDemoCommand = onRunDemoRedTeamCommand
      )
      else -> Mode3ControlScreen(
        config = config,
        isOnline = isOnline,
        onPushDaemonConfig = onPushDaemonConfig,
        onToggleDemoMode = onToggleDemoMode,
        onOpenDaemonSettings = onOpenDaemonSettings
      )
    }
  }
}

@Composable
fun GateModeTab(
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
      .testTag("gate_mode_tab_$mode"),
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

@Composable
private fun Mode1ControlScreen(
  config: HoneygateConfigEntity,
  authResult: Mode1AuthResult?,
  otpChallenge: OtpChallenge?,
  onPushDaemonConfig: (DaemonConfigUpdate) -> Unit,
  onToggleDemoMode: (Boolean) -> Unit,
  onRegisterDemo: (String, String, String) -> Unit,
  onRequestDemoOtp: (String, String, String) -> Unit,
  onVerifyDemoOtp: (String, String, String) -> Boolean,
  onDismissOtp: () -> Unit,
  onClearResult: () -> Unit,
  onUpdateBranding: (String, String, String) -> Unit
) {
  var maxEmailsInput by remember(config.sybilMaxEmailsPerDevice) { mutableStateOf(config.sybilMaxEmailsPerDevice.toString()) }
  var sybilWindowInput by remember(config.sybilWindowSeconds) { mutableStateOf(config.sybilWindowSeconds.toString()) }
  var isBrandingExpanded by remember { mutableStateOf(false) }
  var companyNameInput by remember(config.companyName) { mutableStateOf(config.companyName) }

  // Estados DEMO únicamente usados cuando demoModeEnabled == true
  var demoEmailInput by remember { mutableStateOf("") }
  var demoOtpInput by remember { mutableStateOf("") }
  var demoOtpError by remember { mutableStateOf(false) }
  var demoIpInput by remember { mutableStateOf("192.168.1.105") }
  var demoMacInput by remember { mutableStateOf("52:54:00:12:34:56") }

  LazyColumn(
    modifier = Modifier.fillMaxSize(),
    verticalArrangement = Arrangement.spacedBy(10.dp),
    contentPadding = PaddingValues(bottom = 24.dp)
  ) {
    // Configuración real de Modo 1 en el daemon
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, CyberGreen.copy(alpha = 0.5f))
      ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Text("Parámetros del Daemon — Modo 1 (/api/config)", fontWeight = FontWeight.Bold, color = CyberGreen, fontSize = 12.sp)

          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Column(modifier = Modifier.weight(1f)) {
              Text("portal_enabled", fontSize = 11.sp, color = TextPrimary, fontFamily = FontFamily.Monospace)
              Text("Habilita registro con correo y consentimiento Ley 25.326", fontSize = 9.sp, color = TextMuted)
            }
            Switch(
              checked = config.portalEnabled,
              onCheckedChange = { onPushDaemonConfig(DaemonConfigUpdate(portalEnabled = it)) },
              modifier = Modifier.testTag("switch_portal_enabled")
            )
          }

          Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
              value = maxEmailsInput,
              onValueChange = { maxEmailsInput = it.filter { ch -> ch.isDigit() } },
              label = { Text("sybil_max_emails_per_device", fontSize = 9.sp) },
              singleLine = true,
              modifier = Modifier.weight(1f),
              textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
            )
            OutlinedTextField(
              value = sybilWindowInput,
              onValueChange = { sybilWindowInput = it.filter { ch -> ch.isDigit() } },
              label = { Text("sybil_window_seconds", fontSize = 9.sp) },
              singleLine = true,
              modifier = Modifier.weight(1f),
              textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
            )
          }

          Button(
            onClick = {
              val maxE = maxEmailsInput.toIntOrNull()?.coerceIn(1, 100) ?: config.sybilMaxEmailsPerDevice
              val winS = sybilWindowInput.toIntOrNull()?.coerceIn(10, 86400) ?: config.sybilWindowSeconds
              onPushDaemonConfig(
                DaemonConfigUpdate(
                  sybilMaxEmailsPerDevice = maxE,
                  sybilWindowSeconds = winS
                )
              )
            },
            modifier = Modifier.fillMaxWidth().testTag("apply_mode1_daemon_config"),
            colors = ButtonDefaults.buttonColors(containerColor = CyberGreen, contentColor = Color.Black)
          ) {
            Text("Aplicar Reglas Anti-Sybil en Daemon", fontSize = 11.sp, fontWeight = FontWeight.Bold)
          }
        }
      }
    }

    // Aviso Legal Invariante 4
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF131B26)),
        border = androidx.compose.foundation.BorderStroke(1.dp, CyanGlow)
      ) {
        Column(modifier = Modifier.padding(10.dp)) {
          Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Icon(Icons.Default.Gavel, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(16.dp))
            Text("Marco Legal (Ley 25.326 y Ley 26.388)", fontWeight = FontWeight.Bold, color = CyberCyan, fontSize = 11.sp)
          }
          Spacer(modifier = Modifier.height(4.dp))
          Text(
            "El portal registra únicamente correo de contacto y metadatos técnicos con consentimiento explícito, nunca contraseñas. Uso restringido a redes propias o autorizadas.",
            fontSize = 10.sp,
            color = TextSecondary,
            lineHeight = 14.sp
          )
        }
      }
    }

    // Personalización local visual del panel
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
      ) {
        Column(modifier = Modifier.padding(12.dp)) {
          Row(
            modifier = Modifier
              .fillMaxWidth()
              .clickable { isBrandingExpanded = !isBrandingExpanded },
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Text("Preferencias Visuales del Panel", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 12.sp)
            Icon(
              imageVector = if (isBrandingExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
              contentDescription = null,
              tint = TextSecondary
            )
          }
          AnimatedVisibility(visible = isBrandingExpanded) {
            Column(modifier = Modifier.padding(top = 8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
              OutlinedTextField(
                value = companyNameInput,
                onValueChange = {
                  companyNameInput = it
                  onUpdateBranding(companyNameInput, config.primaryColorHex, config.accentColorHex)
                },
                label = { Text("Etiqueta de organización (solo vista local)", fontSize = 10.sp) },
                modifier = Modifier.fillMaxWidth().testTag("company_name_input"),
                singleLine = true,
                textStyle = androidx.compose.ui.text.TextStyle(fontSize = 12.sp, color = TextPrimary)
              )
            }
          }
        }
      }
    }

    // Bloque Modo DEMO explícito
    item {
      DemoModeControlCard(
        demoEnabled = config.demoModeEnabled,
        onToggleDemoMode = onToggleDemoMode
      )
    }

    if (config.demoModeEnabled) {
      item {
        Card(
          modifier = Modifier.fillMaxWidth(),
          shape = RoundedCornerShape(12.dp),
          colors = CardDefaults.cardColors(containerColor = DarkSurface),
          border = androidx.compose.foundation.BorderStroke(1.dp, WarningAmber.copy(alpha = 0.6f))
        ) {
          Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("[DEMO] Simulador Local Portal Modo 1", fontWeight = FontWeight.Bold, color = WarningAmber, fontSize = 12.sp)
            OutlinedTextField(
              value = demoEmailInput,
              onValueChange = { demoEmailInput = it },
              label = { Text("Email de prueba DEMO", fontSize = 10.sp) },
              modifier = Modifier.fillMaxWidth().testTag("mode1_email_input"),
              singleLine = true,
              textStyle = androidx.compose.ui.text.TextStyle(fontSize = 12.sp, color = TextPrimary)
            )
            if (otpChallenge == null) {
              Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                  onClick = { if (demoEmailInput.isNotBlank()) onRequestDemoOtp(demoEmailInput, demoIpInput, demoMacInput) },
                  colors = ButtonDefaults.buttonColors(containerColor = WarningAmber, contentColor = Color.Black),
                  modifier = Modifier.weight(1f).testTag("mode1_send_otp_button")
                ) {
                  Text("Probar OTP DEMO", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                }
                OutlinedButton(
                  onClick = { if (demoEmailInput.isNotBlank()) onRegisterDemo(demoEmailInput, demoIpInput, demoMacInput) },
                  modifier = Modifier.weight(1f).testTag("mode1_register_button")
                ) {
                  Text("Registro DEMO", fontSize = 10.sp)
                }
              }
            } else {
              Text("[DEMO] PIN temporal local: ${otpChallenge.code}", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = WarningAmber)
              Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                  value = demoOtpInput,
                  onValueChange = {
                    demoOtpInput = it
                    demoOtpError = false
                  },
                  label = { Text("PIN", fontSize = 10.sp) },
                  modifier = Modifier.weight(1f).testTag("otp_code_input"),
                  singleLine = true
                )
                Button(
                  onClick = { demoOtpError = !onVerifyDemoOtp(demoOtpInput, demoIpInput, demoMacInput) },
                  modifier = Modifier.testTag("verify_otp_button")
                ) {
                  Text("Validar", fontSize = 10.sp)
                }
                IconButton(onClick = onDismissOtp) {
                  Icon(Icons.Default.Close, contentDescription = "Cerrar OTP")
                }
              }
              if (demoOtpError) {
                Text("PIN incorrecto", fontSize = 9.sp, color = AlertRed)
              }
            }

            authResult?.let { res ->
              Surface(
                shape = RoundedCornerShape(8.dp),
                color = AmberGlow,
                border = androidx.compose.foundation.BorderStroke(1.dp, WarningAmber),
                modifier = Modifier.fillMaxWidth()
              ) {
                Row(modifier = Modifier.padding(8.dp), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                  Text(res.message, fontSize = 10.sp, color = TextPrimary, modifier = Modifier.weight(1f))
                  IconButton(onClick = onClearResult, modifier = Modifier.size(18.dp)) {
                    Icon(Icons.Default.Close, contentDescription = null, modifier = Modifier.size(12.dp))
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

@Composable
private fun Mode2ControlScreen(
  config: HoneygateConfigEntity,
  redTeamLogs: List<String>,
  escalationLevel: String,
  onPushDaemonConfig: (DaemonConfigUpdate) -> Unit,
  onToggleDemoMode: (Boolean) -> Unit,
  onRunDemoCommand: (String, String) -> Unit
) {
  var maxOutboundInput by remember(config.maxOutboundPerMinute) { mutableStateOf(config.maxOutboundPerMinute.toString()) }
  var whitelistInput by remember(config.allowedOutboundWhitelistCsv) { mutableStateOf(config.allowedOutboundWhitelistCsv) }
  var demoCmdText by remember { mutableStateOf("") }

  LazyColumn(
    modifier = Modifier.fillMaxSize(),
    verticalArrangement = Arrangement.spacedBy(10.dp),
    contentPadding = PaddingValues(bottom = 24.dp)
  ) {
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, AlertRed.copy(alpha = 0.5f))
      ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Text("Parámetros del Daemon — Modo 2 (/api/config)", fontWeight = FontWeight.Bold, color = AlertRed, fontSize = 12.sp)

          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Column(modifier = Modifier.weight(1f)) {
              Text("honeypot_enabled", fontSize = 11.sp, color = TextPrimary, fontFamily = FontFamily.Monospace)
              Text("Activa servicios emulados sin conexiones salientes", fontSize = 9.sp, color = TextMuted)
            }
            Switch(
              checked = config.honeypotEnabled,
              onCheckedChange = { onPushDaemonConfig(DaemonConfigUpdate(honeypotEnabled = it)) },
              modifier = Modifier.testTag("switch_honeypot_enabled")
            )
          }

          OutlinedTextField(
            value = maxOutboundInput,
            onValueChange = { maxOutboundInput = it.filter { ch -> ch.isDigit() } },
            label = { Text("max_outbound_per_minute", fontSize = 10.sp) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
          )

          OutlinedTextField(
            value = whitelistInput,
            onValueChange = { whitelistInput = it },
            label = { Text("egress_whitelist (separada por comas)", fontSize = 10.sp) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
          )

          Button(
            onClick = {
              val rate = maxOutboundInput.toIntOrNull()?.coerceIn(1, 10000) ?: config.maxOutboundPerMinute
              val wl = whitelistInput.split(",").map { it.trim() }.filter { it.isNotEmpty() }
              onPushDaemonConfig(
                DaemonConfigUpdate(
                  maxOutboundPerMinute = rate,
                  egressWhitelist = wl
                )
              )
            },
            modifier = Modifier.fillMaxWidth().testTag("apply_mode2_daemon_config"),
            colors = ButtonDefaults.buttonColors(containerColor = AlertRed, contentColor = Color.White)
          ) {
            Text("Guardar Política de Contención en Daemon", fontSize = 11.sp, fontWeight = FontWeight.Bold)
          }
        }
      }
    }

    item {
      DemoModeControlCard(
        demoEnabled = config.demoModeEnabled,
        onToggleDemoMode = onToggleDemoMode
      )
    }

    if (config.demoModeEnabled) {
      item {
        Card(
          modifier = Modifier.fillMaxWidth(),
          shape = RoundedCornerShape(10.dp),
          colors = CardDefaults.cardColors(containerColor = Color(0xFF090D14)),
          border = androidx.compose.foundation.BorderStroke(1.dp, WarningAmber.copy(alpha = 0.6f))
        ) {
          Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
              Text("[DEMO] Consola Local de Pruebas", fontWeight = FontWeight.Bold, color = WarningAmber, fontSize = 11.sp)
              Text(escalationLevel, fontSize = 10.sp, color = WarningAmber)
            }
            Box(
              modifier = Modifier
                .fillMaxWidth()
                .height(100.dp)
                .clip(RoundedCornerShape(6.dp))
                .background(Color.Black)
                .padding(8.dp)
            ) {
              if (redTeamLogs.isEmpty()) {
                Text("Sin comandos DEMO ejecutados.", color = TextMuted, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
              } else {
                LazyColumn(modifier = Modifier.fillMaxSize()) {
                  items(redTeamLogs) { line ->
                    Text(line, color = CyberGreen, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                  }
                }
              }
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
              OutlinedTextField(
                value = demoCmdText,
                onValueChange = { demoCmdText = it },
                placeholder = { Text("Comando de prueba DEMO...", fontSize = 10.sp) },
                modifier = Modifier.weight(1f),
                singleLine = true,
                textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = CyberGreen)
              )
              Button(
                onClick = {
                  if (demoCmdText.isNotBlank()) {
                    onRunDemoCommand("canary_demo", demoCmdText)
                    demoCmdText = ""
                  }
                },
                colors = ButtonDefaults.buttonColors(containerColor = WarningAmber, contentColor = Color.Black)
              ) {
                Text("Probar", fontSize = 10.sp, fontWeight = FontWeight.Bold)
              }
            }
          }
        }
      }
    }
  }
}

@Composable
private fun Mode3ControlScreen(
  config: HoneygateConfigEntity,
  isOnline: Boolean,
  onPushDaemonConfig: (DaemonConfigUpdate) -> Unit,
  onToggleDemoMode: (Boolean) -> Unit,
  onOpenDaemonSettings: () -> Unit
) {
  var retentionInput by remember(config.retentionDays) { mutableStateOf(config.retentionDays.toString()) }

  LazyColumn(
    modifier = Modifier.fillMaxSize(),
    verticalArrangement = Arrangement.spacedBy(10.dp),
    contentPadding = PaddingValues(bottom = 24.dp)
  ) {
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan.copy(alpha = 0.5f))
      ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Text("Modo 3: Control Mixto (/api/config)", fontWeight = FontWeight.Bold, color = CyberCyan, fontSize = 12.sp)
          Text("Todos los cambios se escriben directamente en SQLite del daemon vía PUT /api/config.", fontSize = 10.sp, color = TextSecondary)

          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Text("portal_enabled", fontSize = 11.sp, color = TextPrimary, fontFamily = FontFamily.Monospace)
            Switch(
              checked = config.portalEnabled,
              onCheckedChange = { onPushDaemonConfig(DaemonConfigUpdate(portalEnabled = it)) }
            )
          }

          Divider(color = DarkBorder)

          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Text("honeypot_enabled", fontSize = 11.sp, color = TextPrimary, fontFamily = FontFamily.Monospace)
            Switch(
              checked = config.honeypotEnabled,
              onCheckedChange = { onPushDaemonConfig(DaemonConfigUpdate(honeypotEnabled = it)) }
            )
          }

          Divider(color = DarkBorder)

          Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
              value = retentionInput,
              onValueChange = { retentionInput = it.filter { ch -> ch.isDigit() } },
              label = { Text("retention_days", fontSize = 10.sp) },
              singleLine = true,
              modifier = Modifier.weight(1f),
              textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
            )
            Button(
              onClick = {
                val days = retentionInput.toIntOrNull()?.coerceIn(1, 3650) ?: config.retentionDays
                onPushDaemonConfig(DaemonConfigUpdate(retentionDays = days))
              },
              colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black)
            ) {
              Text("Guardar", fontSize = 11.sp, fontWeight = FontWeight.Bold)
            }
          }
        }
      }
    }

    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, if (isOnline) CyberGreen.copy(alpha = 0.4f) else AlertRed.copy(alpha = 0.4f))
      ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
          Text("Estado de Conexión al Daemon", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 12.sp)
          Text("Endpoint: ${config.daemonBaseUrl}", fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = CyberCyan)
          Text("Estado actual: ${if (isOnline) "Conectado" else "Sin conexión"}", fontSize = 10.sp, color = if (isOnline) CyberGreen else AlertRed)
          OutlinedButton(
            onClick = onOpenDaemonSettings,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberCyan),
            border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan)
          ) {
            Icon(Icons.Default.Settings, contentDescription = null, modifier = Modifier.size(14.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("Configurar URL / Token / Sincronizar", fontSize = 11.sp)
          }
        }
      }
    }

    item {
      DemoModeControlCard(
        demoEnabled = config.demoModeEnabled,
        onToggleDemoMode = onToggleDemoMode
      )
    }
  }
}

@Composable
private fun DemoModeControlCard(
  demoEnabled: Boolean,
  onToggleDemoMode: (Boolean) -> Unit
) {
  Card(
    modifier = Modifier.fillMaxWidth(),
    shape = RoundedCornerShape(10.dp),
    colors = CardDefaults.cardColors(containerColor = if (demoEnabled) AmberGlow else DarkSurface),
    border = androidx.compose.foundation.BorderStroke(1.dp, if (demoEnabled) WarningAmber else DarkBorder)
  ) {
    Row(
      modifier = Modifier.padding(12.dp).fillMaxWidth(),
      horizontalArrangement = Arrangement.SpaceBetween,
      verticalAlignment = Alignment.CenterVertically
    ) {
      Column(modifier = Modifier.weight(1f)) {
        Text(
          text = if (demoEnabled) "Modo DEMO: ACTIVO" else "Modo DEMO (apagado por defecto)",
          fontWeight = FontWeight.Bold,
          fontSize = 11.sp,
          color = if (demoEnabled) WarningAmber else TextPrimary
        )
        Text(
          text = if (demoEnabled) {
            "Genera datos locales marcados [DEMO] sin daemon."
          } else {
            "Panel en modo real: lee y escribe solo contra el daemon."
          },
          fontSize = 10.sp,
          color = TextSecondary
        )
      }
      Switch(
        checked = demoEnabled,
        onCheckedChange = onToggleDemoMode
      )
    }
  }
}
