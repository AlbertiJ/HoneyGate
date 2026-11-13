package com.example.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Caché local y preferencias de conexión del panel de control HoneyGate.
 * Los parámetros operativos (mode, retention_days, max_outbound_per_minute, portal_enabled,
 * honeypot_enabled, egress_whitelist, sybil_*) se sincronizan con GET/PUT /api/config.
 */
@Entity(tableName = "honeygate_config")
data class HoneygateConfigEntity(
  @PrimaryKey
  val id: Int = 1,
  val gateMode: Int = 1, // mode: 1, 2 o 3
  val retentionDays: Int = 30,
  val maxOutboundPerMinute: Int = 10,
  val portalEnabled: Boolean = true,
  val honeypotEnabled: Boolean = false,
  val allowedOutboundWhitelistCsv: String = "",
  val sybilMaxEmailsPerDevice: Int = 3,
  val sybilWindowSeconds: Int = 600,
  val configUpdatedAtSec: Double = 0.0,

  // Branding local del panel (no se envía como campo extra a PUT /api/config)
  val companyName: String = "HoneyGate",
  val primaryColorHex: String = "#10B981",
  val accentColorHex: String = "#06B6D4",

  // Conector Daemon Linux y estado de caché
  val daemonBaseUrl: String = "http://10.0.2.2:8888",
  val daemonAuthToken: String = "",
  val daemonSyncEnabled: Boolean = true,
  val lastSyncedAtMs: Long = 0L,

  // Modo DEMO explícito, desactivado por defecto
  val demoModeEnabled: Boolean = false
)
