package com.example.data.local.dao

import androidx.room.*
import com.example.data.local.entity.MonitoredSessionEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface MonitoredSessionDao {
  @Query("SELECT * FROM monitored_sessions ORDER BY connectedAt DESC, id DESC")
  fun getAllSessions(): Flow<List<MonitoredSessionEntity>>

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertOrUpdate(session: MonitoredSessionEntity): Long

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertAll(sessions: List<MonitoredSessionEntity>)

  @Query("DELETE FROM monitored_sessions WHERE isDemo = :isDemo")
  suspend fun clearByDemoFlag(isDemo: Boolean)
}
