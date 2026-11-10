package com.example.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Esquema unificado de sesión de HoneyGate.
 * Invariante 1: Identificación mediante Fingerprint Compuesto (device_id) =
 * MAC-por-SSID + Fingerprint de Navegador + Network/JA3 + DHCP fingerprint.
 * Invariante 2: Contención de salida (whitelist / sinkhole).
 * Invariante 4: Consentimiento explícito de metadatos (Ley 25.326 y Ley 26.388).
 */
@Entity(tableName = "monitored_sessions")
data class MonitoredSessionEntity(
  @PrimaryKey(autoGenerate = true)
  val id: Long = 0,
  val deviceId: String, // Fingerprint compuesto inmutable
  val macAddress: String,
  val ipAddress: String,
  val deviceType: String = "Mobile / Chrome OS",
  val browserFingerprint: String = "Canvas_A9F1_JA3_771",
  val dhcpFingerprint: String = "Option55_1,15,3,6_VendorAndroid",
  val ja3Fingerprint: String = "771,4865-4866-4867,0-23-65281-10-11,29-23-24,0",
  val connectedAt: Long = System.currentTimeMillis(),
  val lastActivity: Long = System.currentTimeMillis(),
  val durationSeconds: Long = 0,
  val dhcpLeaseSeconds: Int = 3600,
  val emailsUsedCsv: String = "", // Emails registrados por este device_id
  val failedLoginAttempts: Int = 0,
  val isEmailDisabled: Boolean = false,
  val isMacBlocked: Boolean = false,
  val isInObservation: Boolean = false, // Anti-Sybil: en observación (baja lease y BW)
  val outboundRequestsCount: Int = 0,
  val visitedUrlsCsv: String = "",
  val destinationWhitelisted: Boolean = false,
  val consentAccepted: Boolean = true, // Ley 25.326 AR
  val detectedAnomaliesCsv: String = "",
  val currentStatus: String = "Normal" // "Normal", "Alerted", "Blocked"
)
