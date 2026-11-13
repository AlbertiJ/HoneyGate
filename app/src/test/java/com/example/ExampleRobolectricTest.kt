package com.example

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.example.data.local.HoneyGateDatabase
import com.example.data.remote.HoneyGateDaemonClient
import com.example.data.repository.HoneyGateRepository
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ExampleRobolectricTest {

  private lateinit var db: HoneyGateDatabase
  private lateinit var repository: HoneyGateRepository

  @Before
  fun setup() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    db = Room.inMemoryDatabaseBuilder(context, HoneyGateDatabase::class.java)
      .allowMainThreadQueries()
      .build()
    repository = HoneyGateRepository(
      db.forensicEventDao(),
      db.monitoredSessionDao(),
      db.honeygateConfigDao()
    )
  }

  @After
  fun tearDown() {
    db.close()
  }

  @Test
  fun `read string from context`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val appName = context.getString(R.string.app_name)
    assertEquals("HoneyGate", appName)
  }

  @Test
  fun `room starts empty without preseeded fake sessions or events and demo disabled`() = runBlocking {
    repository.preseedInitialDataIfEmpty()
    val cfg = repository.getConfigOnce()!!
    val events = repository.allEvents.first()
    val sessions = repository.allSessions.first()

    assertFalse(cfg.demoModeEnabled)
    assertEquals("", cfg.daemonAuthToken)
    assertEquals(0, events.size)
    assertEquals(0, sessions.size)
  }

  @Test
  fun `parse real daemon config sessions and events with nullable fields`() {
    val cfgJson = """
      {
        "mode": 2,
        "retention_days": 45,
        "max_outbound_per_minute": 15,
        "portal_enabled": true,
        "honeypot_enabled": true,
        "egress_whitelist": ["10.0.0.10"],
        "sybil_max_emails_per_device": 3,
        "sybil_window_seconds": 600,
        "updated_at": 1700000000.5
      }
    """.trimIndent()
    val cfg = HoneyGateDaemonClient.parseConfigJson(cfgJson)
    assertEquals(2, cfg.mode)
    assertEquals(45, cfg.retentionDays)
    assertEquals(15, cfg.maxOutboundPerMinute)
    assertTrue(cfg.honeypotEnabled)
    assertEquals(listOf("10.0.0.10"), cfg.egressWhitelist)

    val sessionsJson = """
      {
        "sessions": [
          {
            "id": 42,
            "mode": 1,
            "origin": {
              "device_id": "net:127.0.0.1:00:00:00:00:00:00",
              "mac": "00:00:00:00:00:00",
              "ip": "127.0.0.1",
              "client_port": 54644,
              "device_type": "unknown",
              "fingerprints": { "browser": "", "network": "", "dhcp": "" }
            },
            "target": {
              "dest_ip": "127.0.0.1",
              "dest_port": 32222,
              "service": "ssh",
              "honeytoken_touched": null
            },
            "session": {
              "started_at": 1700000000.0,
              "ended_at": null,
              "duration_sec": 3.5,
              "status": "en_observacion",
              "bytes_in": 120,
              "bytes_out": 80,
              "observed_reason": "Prueba"
            },
            "visitor_label": null
          }
        ],
        "total": 1,
        "limit": 50,
        "offset": 0
      }
    """.trimIndent()
    val sessPage = HoneyGateDaemonClient.parseSessionsPageJson(sessionsJson)
    assertEquals(1, sessPage.total)
    val sessDto = sessPage.sessions[0]
    assertEquals(42L, sessDto.id)
    assertEquals("en_observacion", sessDto.status)
    assertNull(sessDto.honeytokenTouched)
    assertNull(sessDto.visitorLabel)
    val sessEntity = HoneyGateRepository.mapSessionDtoToEntity(sessDto)
    assertEquals(42L, sessEntity.daemonSessionId)
    assertTrue(sessEntity.isInObservation)
    assertEquals("", sessEntity.visitorLabel)

    val eventsJson = """
      {
        "events": [
          {
            "id": 99,
            "session_id": null,
            "timestamp": 1700000010.0,
            "created_at": "2026-11-13 04:36:45",
            "mode": 2,
            "device_id": null,
            "ip": null,
            "event_type": "CONFIG_UPDATED",
            "severity": "info",
            "mitre_technique": null,
            "description": "Configuración actualizada vía API",
            "metadata": {}
          }
        ],
        "total": 1,
        "limit": 50,
        "offset": 0
      }
    """.trimIndent()
    val evPage = HoneyGateDaemonClient.parseEventsPageJson(eventsJson)
    val evDto = evPage.events[0]
    assertNull(evDto.deviceId)
    assertNull(evDto.ip)
    assertNull(evDto.mitreTechnique)
    val evEntity = HoneyGateRepository.mapEventDtoToEntity(evDto)
    assertEquals("", evEntity.deviceId)
    assertEquals("", evEntity.sourceIp)
    assertEquals("", evEntity.mitreTechnique)
    assertEquals("CONFIG_UPDATED", evEntity.rawEventType)
  }

  @Test
  fun `disabling demo mode removes demo data and preserves real cache`() = runBlocking {
    repository.preseedInitialDataIfEmpty()
    repository.setDemoMode(true)
    repository.runDemoMode1Registration("test@tempmail.com", "10.0.0.5", "aa:bb:cc:dd:ee:ff")
    assertTrue(repository.allSessions.first().any { it.isDemo })
    assertTrue(repository.allEvents.first().any { it.isDemo })

    repository.setDemoMode(false)
    assertEquals(0, repository.allSessions.first().size)
    assertEquals(0, repository.allEvents.first().size)
  }
}
