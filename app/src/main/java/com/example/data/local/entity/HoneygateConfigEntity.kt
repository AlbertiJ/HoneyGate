package com.example.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Entidad Room para persistir la configuración de la Puerta de Miel / Honeygate
 * en sus 3 modos operativos.
 */
@Entity(tableName = "honeygate_config")
data class HoneygateConfigEntity(
  @PrimaryKey
  val id: Int = 1,
  val gateMode: Int = 1, // 1: Portal Corporativo, 2: Ejercicio Red Team, 3: Proxy Deceptivo Unificado
  val companyName: String = "Corporación AeroSec Global",
  val logoTag: String = "SHIELD_SECURITY",
  val primaryColorHex: String = "#00FF66",
  val accentColorHex: String = "#00D4FF",
  val compromisedAreas: String = "Finanzas y Tesorería, Infraestructura Cloud DevOps",
  val canaryUsersCsv: String = "admin_sec@aerosec.corp, jdoe_dev@aerosec.corp, cfo_pay@aerosec.corp",
  val simulatedServicesActive: Boolean = true,
  val transparentProxyEnabled: Boolean = true,
  val maxOutboundThreshold: Int = 10
)
