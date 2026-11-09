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
import com.example.ui.screens.AdminSessionsScreen
import com.example.ui.screens.BlueTeamReportScreen
import com.example.ui.screens.ForensicEventsScreen
import com.example.ui.screens.HoneygateScreen
import com.example.ui.theme.*
import com.example.ui.viewmodel.UndahwoarViewModel

class MainActivity : ComponentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    enableEdgeToEdge()
    setContent {
      MyApplicationTheme {
        UndahwoarMainApp()
      }
    }
  }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UndahwoarMainApp(viewModel: UndahwoarViewModel = viewModel()) {
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
  val authResult by viewModel.lastAuthResult.collectAsStateWithLifecycle()
  val redTeamLogs by viewModel.redTeamTerminalHistory.collectAsStateWithLifecycle()
  val escalationLevel by viewModel.escalationLevel.collectAsStateWithLifecycle()

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
                text = "UNDAHWOAR HONEYWALL",
                fontWeight = FontWeight.Bold,
                fontSize = 15.sp,
                letterSpacing = 1.sp,
                color = TextPrimary
              )
              Text(
                text = "Puerta de Miel & Monitoreo Forense (Room Persisted)",
                fontSize = 11.sp,
                color = CyberCyan
              )
            }
          }
        },
        actions = {
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
              Text("Room DB", fontSize = 11.sp, color = CyberGreen, fontWeight = FontWeight.SemiBold)
            }
          }
        }
      )
    },
    bottomBar = {
      NavigationBar(
        containerColor = DarkSurface,
        contentColor = TextPrimary,
        tonalElevation = 8.dp,
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
          onBlockMac = { viewModel.blockMac(it) },
          onDeleteEvent = { /* Event deletion */ }
        )
        1 -> HoneygateScreen(
          config = honeygateConfig,
          authResult = authResult,
          redTeamLogs = redTeamLogs,
          escalationLevel = escalationLevel,
          onSaveConfig = { viewModel.saveConfig(it) },
          onSubmitAuth = { ip, mac, email, pass, otp ->
            viewModel.submitHoneygateAuth(ip, mac, email, pass, otp)
          },
          onSimulateRedTeamCommand = { cmd, canaryUser ->
            viewModel.simulateRedTeamCommand(cmd, canaryUser)
          },
          onClearAuthResult = { viewModel.clearAuthResult() }
        )
        2 -> AdminSessionsScreen(
          sessions = sessions,
          onBlockMac = { viewModel.blockMac(it) },
          onUnblockMac = { viewModel.unblockMac(it) }
        )
        3 -> BlueTeamReportScreen(
          reportText = viewModel.generateBlueTeamReport()
        )
      }
    }
  }
}

data class NavigationTabItem(
  val label: String,
  val icon: ImageVector
)
