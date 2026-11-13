package com.example.data.local.dao

import androidx.room.*
import com.example.data.local.entity.HoneygateConfigEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface HoneygateConfigDao {
  @Query("SELECT * FROM honeygate_config WHERE id = 1 LIMIT 1")
  fun getConfig(): Flow<HoneygateConfigEntity?>

  @Query("SELECT * FROM honeygate_config WHERE id = 1 LIMIT 1")
  suspend fun getConfigOnce(): HoneygateConfigEntity?

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun saveConfig(config: HoneygateConfigEntity)
}
