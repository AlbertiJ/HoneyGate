package com.example.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import com.example.data.local.dao.ForensicEventDao
import com.example.data.local.dao.HoneygateConfigDao
import com.example.data.local.dao.MonitoredSessionDao
import com.example.data.local.entity.ForensicEvent
import com.example.data.local.entity.HoneygateConfigEntity
import com.example.data.local.entity.MonitoredSessionEntity

@Database(
  entities = [
    ForensicEvent::class,
    MonitoredSessionEntity::class,
    HoneygateConfigEntity::class
  ],
  version = 2,
  exportSchema = false
)
abstract class HoneyGateDatabase : RoomDatabase() {
  abstract fun forensicEventDao(): ForensicEventDao
  abstract fun monitoredSessionDao(): MonitoredSessionDao
  abstract fun honeygateConfigDao(): HoneygateConfigDao

  companion object {
    @Volatile
    private var INSTANCE: HoneyGateDatabase? = null

    fun getInstance(context: Context): HoneyGateDatabase {
      return INSTANCE ?: synchronized(this) {
        val instance = Room.databaseBuilder(
          context.applicationContext,
          HoneyGateDatabase::class.java,
          "honeygate_security.db"
        )
        .fallbackToDestructiveMigration()
        .build()
        INSTANCE = instance
        instance
      }
    }
  }
}
