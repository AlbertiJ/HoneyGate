package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
    NavigationTabItem("Eventos Forenses", Icons.Default.Shield),
    NavigationTabItem("Puerta de Miel", Icons.Default.DoorSliding),
    NavigationTabItem("Correlación Admin", Icons.Default.AdminPanelSettings),
    NavigationTabItem("Informe Blue Team", Icons.Default.Description)
  )

  // Observación reactiva de estados desde Room Database a través de StateFlow
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
  val sqlInjectionResult by viewModel.sqlInjectionResult.collectAsStateWithLifecycle()
  val redTeamLogs by viewModel.redTeamTerminalHistory.collectAsStateWithLifecycle()
  val escalationLevel by viewModel.escalationLevel.collectAsStateWithLifecycle()

  val daemonStatus by viewModel.daemonStatus.collectAsStateWithLifecycle()
  val isSyncingDaemon by viewModel.isSyncingDaemon.collectAsStateWithLifecycle()
  val daemonSyncMessage by viewModel.daemonSyncMessage.collectAsStateWithLifecycle()
  var showDaemonDialog by remember { mutableStateOf(false) }

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
                text = "Portal Cautivo de Decepción & Telemetría Forense",
                fontSize = 10.sp,
                color = CyberCyan
              )
            }
          }
        },
        actions = {
          DaemonStatusBadge(
            daemonStatus = daemonStatus,
            isSyncing = isSyncingDaemon,
            onClick = { showDaemonDialog = true }
          )
          Spacer(modifier = Modifier.width(6.dp))
          Surface(
            shape = RoundedCornerShape(16.dp),
            color = GreenGlow,
            border = androidx.compose.foundation.BorderStroke(1.dp, CyberGreen),
            modifier = Modifier.padding(end = 12.dp)
          ) {
            Row(
              modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
              verticalAlignment = Alignment.CenterVertically,
              horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
              Box(
                modifier = Modifier
                  .size(8.dp)
                  .clip(CircleShape)
                  .background(CyberGreen)
              )
              Text("Room DB", fontSize = 10.sp, color = CyberGreen, fontWeight = FontWeight.SemiBold)
            }
          }
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
    Box(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding)
    ) {
      when (selectedTab) {
        0 -> ForensicEventsScreen(
          events = events,
          selectedFilter = selectedFilter,
          searchQuery = searchQuery,
          blockedCount = blockedCount,
          alertedCount = alertedCount,
          normalCount = normalCount,
          onFilterSelected = { viewModel.setFilter(it) },
          onSearchQueryChanged = { viewModel.setSearchQuery(it) },
          onBlockMacConfirmed = { mac, devId -> viewModel.blockMacConfirmed(mac, devId) },
          onDeleteEvent = { viewModel.clearAllEvents() }
        )
        1 -> HoneygateScreen(
          config = honeygateConfig,
          mode1Result = mode1Result,
          mode2Result = mode2Result,
          otpChallenge = otpChallenge,
          sqlInjectionResult = sqlInjectionResult,
          redTeamLogs = redTeamLogs,
          escalationLevel = escalationLevel,
          onSaveConfig = { viewModel.saveConfig(it) },
          onRegisterMode1 = { email, ip, mac ->
            viewModel.registerMode1(email, ip, mac)
          },
          onRequestOtp = { email, ip, mac ->
            viewModel.requestOtp(email, ip, mac)
          },
          onVerifyOtp = { code, ip, mac ->
            viewModel.verifyOtpAndRegister(code, ip, mac)
          },
          onDismissOtp = { viewModel.dismissOtpChallenge() },
          onTestSqlInjection = { payload, ip, mac ->
            viewModel.triggerSqlInjectionTest(payload, ip, mac)
          },
          onClearSqlInjection = { viewModel.clearSqlInjectionResult() },
          onRunRedTeamCommand = { user, cmd ->
            viewModel.runRedTeamCommand(user, cmd)
          },
          onClearMode1Result = { viewModel.clearMode1Result() },
          onUpdateBranding = { name, primary, accent ->
            viewModel.updateCompanyBranding(name, primary, accent)
          },
          onOpenDaemonSettings = { showDaemonDialog = true }
        )
        2 -> AdminSessionsScreen(
          sessions = sessions,
          onBlockMacConfirmed = { mac, devId -> viewModel.blockMacConfirmed(mac, devId) },
          onUnblockMacConfirmed = { mac, devId -> viewModel.unblockMacConfirmed(mac, devId) }
        )
        3 -> BlueTeamReportScreen(
          reportText = viewModel.generateAuditReport()
        )
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
        viewModel.updateDaemonConfig(url, token, enabled)
      },
      onClearSyncMessage = { viewModel.clearDaemonMessage() }
    )
  }
}

data class NavigationTabItem(
  val label: String,
  val icon: ImageVector
)
