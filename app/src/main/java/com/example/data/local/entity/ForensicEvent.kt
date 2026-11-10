package com.example.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Entidad Room 'ForensicEvent' requerida para persistir logs del sistema de monitoreo.
 * Incluye campos obligatorios: id, timestamp, eventType (Blocked, Alerted, Normal), sourceIp, macAddress, description.
 * Más los campos del esquema unificado de HoneyGate (deviceId compuesto, técnica MITRE, honeytokens).
 */
@Entity(tableName = "forensic_events")
data class ForensicEvent(
  @PrimaryKey(autoGenerate = true)
  val id: Long = 0,
  val timestamp: Long = System.currentTimeMillis(),
  val eventType: String, // "Blocked", "Alerted", "Normal"
  val sourceIp: String,
  val macAddress: String,
  val description: String,
  val deviceId: String = "", // Fingerprint compuesto (Invariante 1)
  val category: String = "GENERAL_MONITORING",
  val severity: String = "LOW",
  val destinationTarget: String = "127.0.0.1:8080",
  val honeytokenTouched: String? = null,
  val mitreTechnique: String = "T1190 - Exploit Public-Facing Application",
  val isCorrelated: Boolean = false,
  val dateFormatted: String = ""
)
