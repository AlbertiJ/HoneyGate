package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.ui.components.DaemonControlDialog
import com.example.ui.components.DaemonStatusBadge
import com.example.ui.screens.AdminSessionsScreen
import com.example.ui.screens.BlueTeamReportScreen
import com.example.ui.screens.ForensicEventsScreen
import com.example.ui.screens.HoneygateScreen
import com.example.ui.theme.*
import com.example.ui.viewmodel.HoneyGateViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : ComponentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    enableEdgeToEdge()
    setContent {
      MyApplicationTheme {
        HoneyGateMainApp()
      }
    }
  }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HoneyGateMainApp(viewModel: HoneyGateViewModel = viewModel()) {
  var selectedTab by remember { mutableIntStateOf(0) }

  val tabs = listOf(
    NavigationTabItem("Eventos", Icons.Default.Shield),
    NavigationTabItem("Operación", Icons.Default.DoorSliding),
    NavigationTabItem("Sesiones", Icons.Default.AdminPanelSettings),
    NavigationTabItem("Informe", Icons.Default.Description)
  )

  val events by viewModel.eventsList.collectAsStateWithLifecycle()
  val selectedFilter by viewModel.selectedFilter.collectAsStateWithLifecycle()
  val searchQuery by viewModel.searchQuery.collectAsStateWithLifecycle()
  val blockedCount by viewModel.blockedCount.collectAsStateWithLifecycle()
  val alertedCount by viewModel.alertedCount.collectAsStateWithLifecycle()
  val normalCount by viewModel.normalCount.collectAsStateWithLifecycle()

  val sessions by viewModel.sessionsList.collectAsStateWithLifecycle()
  val honeygateConfig by viewModel.honeygateConfig.collectAsStateWithLifecycle()
  val mode1Result by viewModel.mode1Result.collectAsStateWithLifecycle()
  val mode2Result by viewModel.mode2Result.collectAsStateWithLifecycle()
  val otpChallenge by viewModel.otpChallenge.collectAsStateWithLifecycle()
  val redTeamLogs by viewModel.redTeamTerminalHistory.collectAsStateWithLifecycle()
  val escalationLevel by viewModel.escalationLevel.collectAsStateWithLifecycle()

  val daemonStatus by viewModel.daemonStatus.collectAsStateWithLifecycle()
  val isSyncingDaemon by viewModel.isSyncingDaemon.collectAsStateWithLifecycle()
  val daemonSyncMessage by viewModel.daemonSyncMessage.collectAsStateWithLifecycle()
  var showDaemonDialog by remember { mutableStateOf(false) }

  val isOnline = daemonStatus?.online == true

  Scaffold(
    modifier = Modifier.fillMaxSize(),
    containerColor = DarkBackground,
    topBar = {
      TopAppBar(
        colors = TopAppBarDefaults.topAppBarColors(
          containerColor = DarkSurface,
          titleContentColor = TextPrimary
        ),
        title = {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)
          ) {
            Box(
              modifier = Modifier
                .size(36.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(GreenGlow)
                .border(1.dp, CyberGreen, RoundedCornerShape(8.dp)),
              contentAlignment = Alignment.Center
            ) {
              Icon(
                imageVector = Icons.Default.Shield,
                contentDescription = "Shield",
                tint = CyberGreen,
                modifier = Modifier.size(20.dp)
              )
            }
            Column {
              Text(
                text = "HONEYGATE",
                fontWeight = FontWeight.Bold,
                fontSize = 15.sp,
                letterSpacing = 1.sp,
                color = TextPrimary
              )
              Text(
                text = "Panel de Control & Telemetría Forense",
                fontSize = 10.sp,
                color = CyberCyan
              )
            }
          }
        },
        actions = {
          if (honeygateConfig.demoModeEnabled) {
            Surface(
              shape = RoundedCornerShape(16.dp),
              color = AmberGlow,
              border = androidx.compose.foundation.BorderStroke(1.dp, WarningAmber),
              modifier = Modifier
                .padding(end = 6.dp)
                .clickable { showDaemonDialog = true }
                .testTag("demo_badge")
            ) {
              Text(
                text = "DEMO",
                fontSize = 10.sp,
                color = WarningAmber,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
              )
            }
          }
          DaemonStatusBadge(
            daemonStatus = daemonStatus,
            isSyncing = isSyncingDaemon,
            onClick = { showDaemonDialog = true },
            modifier = Modifier.padding(end = 12.dp)
          )
        }
      )
    },
    bottomBar = {
      NavigationBar(
        containerColor = DarkSurface,
        contentColor = TextPrimary,
        tonalElevation = 6.dp,
        windowInsets = WindowInsets.navigationBars
      ) {
        tabs.forEachIndexed { index, tab ->
          val isSelected = selectedTab == index
          NavigationBarItem(
            modifier = Modifier.testTag("nav_tab_$index"),
            selected = isSelected,
            onClick = { selectedTab = index },
            icon = { Icon(tab.icon, contentDescription = tab.label) },
            label = { Text(tab.label, fontSize = 10.sp, maxLines = 1) },
            colors = NavigationBarItemDefaults.colors(
              selectedIconColor = CyberGreen,
              selectedTextColor = CyberGreen,
              indicatorColor = GreenGlow,
              unselectedIconColor = TextMuted,
              unselectedTextColor = TextMuted
            )
          )
        }
      }
    }
  ) { innerPadding ->
    Column(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding)
    ) {
      // Aviso persistente cuando no hay conexión con el daemon (caché obsoleta o vacía)
      if (!isOnline) {
        val lastSyncText = if (honeygateConfig.lastSyncedAtMs > 0L) {
          val fmt = SimpleDateFormat("dd/MM HH:mm:ss", Locale.getDefault()).format(Date(honeygateConfig.lastSyncedAtMs))
          "Sin conexión — mostrando caché local ($fmt)"
        } else {
          "Sin conexión con el daemon (${daemonStatus?.errorMessage ?: "configurá URL y token"})"
        }

        Surface(
          color = RedGlow,
          border = androidx.compose.foundation.BorderStroke(1.dp, AlertRed.copy(alpha = 0.6f)),
          shape = RoundedCornerShape(8.dp),
          modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 14.dp, vertical = 4.dp)
            .clickable { showDaemonDialog = true }
            .testTag("offline_cache_banner")
        ) {
          Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
          ) {
            Row(
              verticalAlignment = Alignment.CenterVertically,
              horizontalArrangement = Arrangement.spacedBy(6.dp),
              modifier = Modifier.weight(1f)
            ) {
              Icon(Icons.Default.CloudOff, contentDescription = "Sin conexión", tint = AlertRed, modifier = Modifier.size(15.dp))
              Text(lastSyncText, fontSize = 10.sp, color = TextPrimary, maxLines = 2)
            }
            Text("Conectar", fontSize = 10.sp, color = CyberCyan, fontWeight = FontWeight.Bold)
          }
        }
      }

      if (daemonSyncMessage != null) {
        Surface(
          color = CyanGlow,
          border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan.copy(alpha = 0.6f)),
          shape = RoundedCornerShape(8.dp),
          modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 14.dp, vertical = 2.dp)
        ) {
          Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
          ) {
            Text(daemonSyncMessage ?: "", fontSize = 10.sp, color = CyberCyan, modifier = Modifier.weight(1f))
            IconButton(onClick = { viewModel.clearDaemonMessage() }, modifier = Modifier.size(20.dp)) {
              Icon(Icons.Default.Close, contentDescription = "Cerrar aviso", tint = CyberCyan, modifier = Modifier.size(14.dp))
            }
          }
        }
      }

      Box(modifier = Modifier.fillMaxSize()) {
        when (selectedTab) {
          0 -> ForensicEventsScreen(
            events = events,
            selectedFilter = selectedFilter,
            searchQuery = searchQuery,
            blockedCount = blockedCount,
            alertedCount = alertedCount,
            normalCount = normalCount,
            isOnline = isOnline,
            onFilterSelected = { viewModel.setFilter(it) },
            onSearchQueryChanged = { viewModel.setSearchQuery(it) },
            onIsolateIpConfirmed = { ip, devId -> viewModel.isolateIpFromEventConfirmed(ip, devId) },
            onDeleteEvent = { viewModel.clearAllEvents() },
            onRefreshFromDaemon = { viewModel.syncDaemonData() }
          )
          1 -> HoneygateScreen(
            config = honeygateConfig,
            isOnline = isOnline,
            mode1Result = mode1Result,
            mode2Result = mode2Result,
            otpChallenge = otpChallenge,
            redTeamLogs = redTeamLogs,
            escalationLevel = escalationLevel,
            onSelectMode = { viewModel.setOperatingMode(it) },
            onPushDaemonConfig = { viewModel.pushConfigToDaemon(it) },
            onToggleDemoMode = { viewModel.toggleDemoMode(it) },
            onRegisterDemoMode1 = { email, ip, mac -> viewModel.registerDemoMode1(email, ip, mac) },
            onRequestDemoOtp = { email, ip, mac -> viewModel.requestDemoOtp(email, ip, mac) },
            onVerifyDemoOtp = { code, ip, mac -> viewModel.verifyDemoOtpAndRegister(code, ip, mac) },
            onDismissOtp = { viewModel.dismissOtpChallenge() },
            onRunDemoRedTeamCommand = { user, cmd -> viewModel.runDemoRedTeamCommand(user, cmd) },
            onClearMode1Result = { viewModel.clearMode1Result() },
            onUpdateBranding = { name, primary, accent -> viewModel.updateCompanyBranding(name, primary, accent) },
            onOpenDaemonSettings = { showDaemonDialog = true }
          )
          2 -> AdminSessionsScreen(
            sessions = sessions,
            isOnline = isOnline,
            onIsolateConfirmed = { session -> viewModel.isolateOrUnblockSessionConfirmed(session, blocked = true) },
            onUnblockConfirmed = { session -> viewModel.isolateOrUnblockSessionConfirmed(session, blocked = false) },
            onObserveConfirmed = { session, reason -> viewModel.observeSessionConfirmed(session, reason) },
            onRefreshFromDaemon = { viewModel.syncDaemonData() }
          )
          3 -> BlueTeamReportScreen(
            reportText = viewModel.generateAuditReport()
          )
        }
      }
    }
  }

  if (showDaemonDialog) {
    DaemonControlDialog(
      config = honeygateConfig,
      daemonStatus = daemonStatus,
      isSyncing = isSyncingDaemon,
      syncMessage = daemonSyncMessage,
      onDismiss = { showDaemonDialog = false },
      onCheckHealth = { viewModel.checkDaemonHealth() },
      onSyncData = { viewModel.syncDaemonData() },
      onUpdateConfig = { url, token, enabled ->
        viewModel.updateDaemonConnectionConfig(url, token, enabled)
      },
      onToggleDemoMode = { viewModel.toggleDemoMode(it) },
      onClearSyncMessage = { viewModel.clearDaemonMessage() }
    )
  }
}

data class NavigationTabItem(
  val label: String,
  val icon: ImageVector
)
