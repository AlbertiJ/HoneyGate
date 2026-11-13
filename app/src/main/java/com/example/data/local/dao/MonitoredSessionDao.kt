package com.example.data.local.dao

import androidx.room.*
import com.example.data.local.entity.MonitoredSessionEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface MonitoredSessionDao {
  @Query("SELECT * FROM monitored_sessions ORDER BY connectedAt DESC, id DESC")
  fun getAllSessions(): Flow<List<MonitoredSessionEntity>>

  @Query("SELECT * FROM monitored_sessions WHERE daemonSessionId = :daemonSessionId LIMIT 1")
  suspend fun getByDaemonSessionId(daemonSessionId: Long): MonitoredSessionEntity?

  @Query("SELECT * FROM monitored_sessions WHERE deviceId = :deviceId LIMIT 1")
  suspend fun getSessionByDeviceId(deviceId: String): MonitoredSessionEntity?

  @Query("SELECT * FROM monitored_sessions WHERE macAddress = :mac LIMIT 1")
  suspend fun getSessionByMac(mac: String): MonitoredSessionEntity?

  @Query("SELECT * FROM monitored_sessions WHERE ipAddress = :ip LIMIT 1")
  suspend fun getSessionByIp(ip: String): MonitoredSessionEntity?

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertOrUpdate(session: MonitoredSessionEntity): Long

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertAll(sessions: List<MonitoredSessionEntity>)

  @Query("UPDATE monitored_sessions SET isMacBlocked = :blocked, currentStatus = CASE WHEN :blocked = 1 THEN 'isolated' ELSE 'closed' END WHERE macAddress = :mac")
  suspend fun setMacBlockedStatus(mac: String, blocked: Boolean)

  @Query("UPDATE monitored_sessions SET isMacBlocked = :blocked, currentStatus = CASE WHEN :blocked = 1 THEN 'isolated' ELSE 'closed' END WHERE deviceId = :deviceId")
  suspend fun setDeviceBlockedStatus(deviceId: String, blocked: Boolean)

  @Query("UPDATE monitored_sessions SET isInObservation = 1, currentStatus = 'en_observacion', observedReason = :reason WHERE daemonSessionId = :daemonSessionId")
  suspend fun setObservationByDaemonId(daemonSessionId: Long, reason: String)

  @Query("DELETE FROM monitored_sessions WHERE isDemo = :isDemo")
  suspend fun clearByDemoFlag(isDemo: Boolean)

  @Query("DELETE FROM monitored_sessions WHERE id = :id")
  suspend fun deleteById(id: Long)

  @Query("DELETE FROM monitored_sessions")
  suspend fun clearAll()
}
