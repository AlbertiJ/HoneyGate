package com.example.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Caché local en Room de las sesiones devueltas por GET /api/sessions del daemon HoneyGate.
 * Mapea los bloques origin, target y session sin valores ficticios prefabricados.
 */
@Entity(tableName = "monitored_sessions")
data class MonitoredSessionEntity(
  @PrimaryKey(autoGenerate = true)
  val id: Long = 0,
  val daemonSessionId: Long? = null,
  val mode: Int = 1,
  val deviceId: String = "",
  val macAddress: String = "",
  val ipAddress: String = "",
  val clientPort: Int = 0,
  val deviceType: String = "",
  val browserFingerprint: String = "",
  val networkFingerprint: String = "",
  val dhcpFingerprint: String = "",
  val destIp: String = "",
  val destPort: Int = 0,
  val service: String = "",
  val honeytokenTouched: String? = null,
  val connectedAt: Long = 0L,
  val endedAt: Long? = null,
  val lastActivity: Long = 0L,
  val durationSeconds: Long = 0L,
  val bytesIn: Long = 0L,
  val bytesOut: Long = 0L,
  val visitorLabel: String = "",
  val observedReason: String = "",
  val isMacBlocked: Boolean = false,
  val isInObservation: Boolean = false,
  val currentStatus: String = "active", // "active", "closed", "isolated", "en_observacion"
  val isDemo: Boolean = false
)
