package com.example.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import com.example.data.local.dao.ForensicEventDao
import com.example.data.local.dao.HoneygateConfigDao
import com.example.data.local.dao.MonitoredSessionDao
import com.example.data.local.entity.ForensicEventEntity
import com.example.data.local.entity.HoneygateConfigEntity
import com.example.data.local.entity.MonitoredSessionEntity

@Database(
  entities = [
    ForensicEventEntity::class,
    MonitoredSessionEntity::class,
    HoneygateConfigEntity::class
  ],
  version = 1,
  exportSchema = false
)
abstract class UndahwoarDatabase : RoomDatabase() {
  abstract fun forensicEventDao(): ForensicEventDao
  abstract fun monitoredSessionDao(): MonitoredSessionDao
  abstract fun honeygateConfigDao(): HoneygateConfigDao

  companion object {
    @Volatile
    private var INSTANCE: UndahwoarDatabase? = null

    fun getInstance(context: Context): UndahwoarDatabase {
      return INSTANCE ?: synchronized(this) {
        val instance = Room.databaseBuilder(
          context.applicationContext,
          UndahwoarDatabase::class.java,
          "undahwoar_security.db"
        )
        .fallbackToDestructiveMigration()
        .build()
        INSTANCE = instance
        instance
      }
    }
  }
}
