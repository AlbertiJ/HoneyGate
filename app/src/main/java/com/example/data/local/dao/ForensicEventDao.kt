package com.example.data.local.dao

import androidx.room.*
import com.example.data.local.entity.ForensicEventEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ForensicEventDao {
  @Query("SELECT * FROM forensic_events ORDER BY timestamp DESC")
  fun getAllEvents(): Flow<List<ForensicEventEntity>>

  @Query("SELECT * FROM forensic_events WHERE status = :status ORDER BY timestamp DESC")
  fun getEventsByStatus(status: String): Flow<List<ForensicEventEntity>>

  @Query("SELECT * FROM forensic_events WHERE category = :category ORDER BY timestamp DESC")
  fun getEventsByCategory(category: String): Flow<List<ForensicEventEntity>>

  @Query("SELECT * FROM forensic_events WHERE macAddress = :mac ORDER BY timestamp DESC")
  fun getEventsByMac(mac: String): Flow<List<ForensicEventEntity>>

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertEvent(event: ForensicEventEntity): Long

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertAll(events: List<ForensicEventEntity>)

  @Query("DELETE FROM forensic_events WHERE id = :id")
  suspend fun deleteEventById(id: Long)

  @Query("DELETE FROM forensic_events")
  suspend fun clearAll()
}
