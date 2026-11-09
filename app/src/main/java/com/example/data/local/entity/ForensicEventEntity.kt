package com.example.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Entidad Room para persistir eventos de seguridad forenses capturados por Undahwoar.
 * Incluye estados fundamentales de contención: 'Blocked', 'Alerted' y 'Normal'.
 */
@Entity(tableName = "forensic_events")
data class ForensicEventEntity(
  @PrimaryKey(autoGenerate = true)
  val id: Long = 0,
  val timestamp: Long = System.currentTimeMillis(),
  val dateFormatted: String,
  val status: String, // "Blocked", "Alerted", "Normal"
  val severity: String, // "CRITICAL", "HIGH", "MEDIUM", "LOW"
  val category: String, // "SQL_INJECTION", "MULTI_USER_MAC", "BRUTE_FORCE", "RATE_LIMIT_PIVOTING", "REDTEAM_EXPLOIT", "PROXY_DNS"
  val title: String,
  val description: String,
  val sourceIp: String,
  val macAddress: String,
  val associatedEmail: String? = null,
  val mitreTechnique: String = "T1190 - Exploit Public-Facing Application",
  val rawPayload: String? = null,
  val isCorrelated: Boolean = false
)
