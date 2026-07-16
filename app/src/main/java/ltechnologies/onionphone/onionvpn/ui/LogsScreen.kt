package ltechnologies.onionphone.onionvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import ltechnologies.onionphone.onionvpn.logging.LogLine
import ltechnologies.onionphone.onionvpn.logging.LogSource
import ltechnologies.onionphone.onionvpn.logging.TunnelLogBuffer

@Composable
fun LogsScreen() {
    var tabIndex by remember { mutableIntStateOf(0) }
    val tabs = listOf("OnionVPN", "DNSCrypt", "Tor")
    val sources = listOf(LogSource.APP, LogSource.DNSCRYPT, LogSource.TOR)

    val appLogs by TunnelLogBuffer.appLogs.collectAsStateWithLifecycle()
    val dnsLogs by TunnelLogBuffer.dnsCryptLogs.collectAsStateWithLifecycle()
    val torLogs by TunnelLogBuffer.torLogs.collectAsStateWithLifecycle()
    val lines = when (sources[tabIndex]) {
        LogSource.APP -> appLogs
        LogSource.DNSCRYPT -> dnsLogs
        LogSource.TOR -> torLogs
    }

    Column(modifier = Modifier.fillMaxSize()) {
        ScrollableTabRow(selectedTabIndex = tabIndex) {
            tabs.forEachIndexed { index, title ->
                Tab(
                    selected = tabIndex == index,
                    onClick = { tabIndex = index },
                    text = { Text(title) },
                )
            }
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Button(onClick = { TunnelLogBuffer.clear(sources[tabIndex]) }) {
                Text("Clear")
            }
            Button(onClick = { TunnelLogBuffer.clearAll() }) {
                Text("Clear all")
            }
        }
        LogList(lines = lines)
    }
}

@Composable
private fun LogList(lines: List<LogLine>) {
    val listState = rememberLazyListState()
    LaunchedEffect(lines.size) {
        if (lines.isNotEmpty()) {
            listState.animateScrollToItem(lines.lastIndex)
        }
    }
    val formatter = remember {
        SimpleDateFormat("HH:mm:ss", Locale.US)
    }
    LazyColumn(
        state = listState,
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        items(lines) { line ->
            Text(
                text = "${formatter.format(Date(line.timestampMs))}  ${line.text}",
                style = MaterialTheme.typography.bodySmall,
                color = if (line.isError) {
                    MaterialTheme.colorScheme.error
                } else {
                    Color.Unspecified
                },
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}
