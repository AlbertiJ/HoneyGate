package com.example.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Entidad Room para trackear sesiones activas e históricas de usuarios y hosts.
 * Permite correlacionar IP y MAC con múltiples correos, intentos fallidos y bloqueo en cascada.
 */
@Entity(tableName = "monitored_sessions")
data class MonitoredSessionEntity(
  @PrimaryKey(autoGenerate = true)
  val id: Long = 0,
  val macAddress: String,
  val ipAddress: String,
  val connectedAt: Long = System.currentTimeMillis(),
  val lastActivity: Long = System.currentTimeMillis(),
  val durationSeconds: Long = 0,
  val emailsUsedCsv: String = "", // Lista separada por comas de emails usados por esta MAC
  val failedLoginAttempts: Int = 0,
  val isEmailDisabled: Boolean = false,
  val isMacBlocked: Boolean = false,
  val outboundRequestsCount: Int = 0,
  val visitedUrlsCsv: String = "", // URLs o destinos monitoreados
  val detectedAnomaliesCsv: String = "",
  val currentStatus: String = "Normal" // "Normal", "Alerted", "Blocked"
)
