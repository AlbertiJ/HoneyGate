package com.example.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Caché local en Room de los eventos entregados por GET /api/events del daemon HoneyGate.
 * No inventa valores por defecto: refleja los campos reales del daemon o marca isDemo = true
 * únicamente cuando el usuario habilita el modo DEMO local.
 */
@Entity(tableName = "forensic_events")
data class ForensicEvent(
  @PrimaryKey(autoGenerate = true)
  val id: Long = 0,
  val daemonEventId: Long? = null,
  val sessionId: Long? = null,
  val timestamp: Long = System.currentTimeMillis(),
  val eventType: String, // Bucket UI derivado de severity/event_type ("Blocked", "Alerted", "Normal")
  val rawEventType: String = "", // event_type exacto devuelto por el daemon
  val mode: Int = 1,
  val sourceIp: String = "",
  val macAddress: String = "",
  val description: String = "",
  val deviceId: String = "",
  val category: String = "", // Igual a event_type del daemon
  val severity: String = "info", // "info", "normal", "warning", "critical"
  val destinationTarget: String = "",
  val honeytokenTouched: String? = null,
  val mitreTechnique: String = "",
  val isCorrelated: Boolean = false,
  val dateFormatted: String = "", // created_at del daemon
  val isDemo: Boolean = false
)
