package com.example.data.local.dao

import androidx.room.*
import com.example.data.local.entity.MonitoredSessionEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface MonitoredSessionDao {
  @Query("SELECT * FROM monitored_sessions ORDER BY lastActivity DESC")
  fun getAllSessions(): Flow<List<MonitoredSessionEntity>>

  @Query("SELECT * FROM monitored_sessions WHERE deviceId = :deviceId LIMIT 1")
  suspend fun getSessionByDeviceId(deviceId: String): MonitoredSessionEntity?

  @Query("SELECT * FROM monitored_sessions WHERE macAddress = :mac LIMIT 1")
  suspend fun getSessionByMac(mac: String): MonitoredSessionEntity?

  @Query("SELECT * FROM monitored_sessions WHERE ipAddress = :ip LIMIT 1")
  suspend fun getSessionByIp(ip: String): MonitoredSessionEntity?

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertOrUpdate(session: MonitoredSessionEntity): Long

  @Query("UPDATE monitored_sessions SET isMacBlocked = :blocked, currentStatus = CASE WHEN :blocked = 1 THEN 'Blocked' ELSE 'Alerted' END WHERE macAddress = :mac")
  suspend fun setMacBlockedStatus(mac: String, blocked: Boolean)

  @Query("UPDATE monitored_sessions SET isMacBlocked = :blocked, currentStatus = CASE WHEN :blocked = 1 THEN 'Blocked' ELSE 'Alerted' END WHERE deviceId = :deviceId")
  suspend fun setDeviceBlockedStatus(deviceId: String, blocked: Boolean)

  @Query("UPDATE monitored_sessions SET isInObservation = :inObservation, dhcpLeaseSeconds = CASE WHEN :inObservation = 1 THEN 300 ELSE 3600 END, currentStatus = 'Alerted' WHERE deviceId = :deviceId")
  suspend fun setObservationStatus(deviceId: String, inObservation: Boolean)

  @Query("DELETE FROM monitored_sessions WHERE id = :id")
  suspend fun deleteById(id: Long)

  @Query("DELETE FROM monitored_sessions")
  suspend fun clearAll()
}
