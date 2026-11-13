package com.example.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Entidad Room para persistir la configuración integral de HoneyGate
 * con soporte para los 3 Modos Operativos y los 5 Invariantes Obligatorios.
 */
@Entity(tableName = "honeygate_config")
data class HoneygateConfigEntity(
  @PrimaryKey
  val id: Int = 1,
  val gateMode: Int = 1, // 1: Cautivo Trazable, 2: Honeypot Red Team, 3: Mixto Unificado
  val companyName: String = "AeroSec Global Defense Corp",
  val portalBrandingActive: Boolean = true,
  val primaryColorHex: String = "#10B981", // Esmeralda suave
  val accentColorHex: String = "#06B6D4",  // Cian sereno

  // Invariante 2: Contención de salida (Data Control)
  val strictEgressContainment: Boolean = true,
  val egressMode: String = "SINKHOLE", // "SINKHOLE", "WHITELIST", "CONTAINED"
  val allowedOutboundWhitelistCsv: String = "dns.google.com, corp.internal.net, updates.aerosec.corp",

  // Invariante 3: Honeytokens controlados por el operador (ficticios/propios)
  val honeytokensActive: Boolean = true,
  val honeytokenUsersCsv: String = "cfo_canary@honeygate.corp, rrhh_lead@honeygate.corp, devops_root@honeygate.corp",
  val honeytokenSecretsCsv: String = "AWS_SECRET_CANARY_X99A, DB_PWD_HONEY_TRAP_2026",

  // Invariante 4: Cumplimiento Legal (Ley 25.326 y Ley 26.388)
  val legalConsentBannerEnabled: Boolean = true,

  // MODO 1: Anti-Sybil y Reglas de Velocidad
  val antiSybilMaxMailsPerDevice: Int = 2,
  val blockedDisposableDomainsCsv: String = "tempmail.com, guerrillamail.com, 10minutemail.com, mailinator.com",

  // MODO 2: Red Team Assume-Breach y Servicios Emulados
  val compromisedSectorsCsv: String = "Finanzas y Tesorería, RRHH y Nóminas, IT e Infraestructura Cloud",
  val emulatedServicesCsv: String = "MySQL DB (3306), Apache Web (8080), SSH Honey (2222), Telnet (2323)",

  // MODO 3: Mixto
  val maxAllowedConnections: Int = 50,
  val activePortsAuditedCsv: String = "80, 443, 2222, 3306, 8080",
  val networkScannerActive: Boolean = true,

  // Conector Live Daemon Linux (Módulo 1)
  val daemonBaseUrl: String = "http://10.0.2.2:8888",
  val daemonAuthToken: String = "",
  val daemonSyncEnabled: Boolean = true
)
