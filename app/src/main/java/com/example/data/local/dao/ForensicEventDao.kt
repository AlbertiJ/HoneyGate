package com.example.data.local.dao

import androidx.room.*
import com.example.data.local.entity.ForensicEvent
import kotlinx.coroutines.flow.Flow

@Dao
interface ForensicEventDao {
  @Query("SELECT * FROM forensic_events ORDER BY timestamp DESC")
  fun getAllEvents(): Flow<List<ForensicEvent>>

  @Query("SELECT * FROM forensic_events WHERE eventType = :eventType ORDER BY timestamp DESC")
  fun getEventsByType(eventType: String): Flow<List<ForensicEvent>>

  @Query("SELECT * FROM forensic_events WHERE deviceId = :deviceId ORDER BY timestamp DESC")
  fun getEventsByDeviceId(deviceId: String): Flow<List<ForensicEvent>>

  @Query("SELECT * FROM forensic_events WHERE macAddress = :mac ORDER BY timestamp DESC")
  fun getEventsByMac(mac: String): Flow<List<ForensicEvent>>

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertEvent(event: ForensicEvent): Long

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertAll(events: List<ForensicEvent>)

  @Query("DELETE FROM forensic_events WHERE id = :id")
  suspend fun deleteEventById(id: Long)

  @Query("DELETE FROM forensic_events WHERE isDemo = :isDemo")
  suspend fun clearByDemoFlag(isDemo: Boolean)

  @Query("DELETE FROM forensic_events")
  suspend fun clearAll()
}

