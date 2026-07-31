package ltechnologies.onionphone.onionvpn.ui

import android.content.Intent
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.PrimaryScrollableTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import ltechnologies.onionphone.onionvpn.core.model.observability.DiagnosticsGate
import ltechnologies.onionphone.onionvpn.core.model.stability.StabilitySeverity
import ltechnologies.onionphone.onionvpn.logging.LogLine
import ltechnologies.onionphone.onionvpn.logging.LogSource
import ltechnologies.onionphone.onionvpn.logging.TunnelLogBuffer
import timber.log.Timber

@Composable
fun LogsScreen() {
    var tabIndex by remember { mutableIntStateOf(0) }
    val tabs = listOf("OnionVPN", "DNSCrypt", "Tor")
    val sources = listOf(LogSource.APP, LogSource.DNSCRYPT, LogSource.TOR)
    val context = LocalContext.current
    val diagnosticsOn by DiagnosticsGate.diagnosticsEnabled.collectAsStateWithLifecycle()

    val appLogs by TunnelLogBuffer.appLogs.collectAsStateWithLifecycle()
    val dnsLogs by TunnelLogBuffer.dnsCryptLogs.collectAsStateWithLifecycle()
    val torLogs by TunnelLogBuffer.torLogs.collectAsStateWithLifecycle()
    val lines = when (sources[tabIndex]) {
        LogSource.APP -> appLogs
        LogSource.DNSCRYPT -> dnsLogs
        LogSource.TOR -> torLogs
    }

    Column(modifier = Modifier.fillMaxSize()) {
        if (!diagnosticsOn) {
            Text(
                text = "Logging disabled — turn off “No logs (privacy)” in Settings to capture " +
                    "TRACE→ERROR pipeline and native logs.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(16.dp),
            )
        }
        PrimaryScrollableTabRow(
            selectedTabIndex = tabIndex,
            containerColor = MaterialTheme.colorScheme.surface,
            edgePadding = 16.dp,
        ) {
            tabs.forEachIndexed { index, title ->
                Tab(
                    selected = tabIndex == index,
                    onClick = { tabIndex = index },
                    text = {
                        Text(
                            title,
                            style = MaterialTheme.typography.labelLarge,
                        )
                    },
                )
            }
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 10.dp)
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilledTonalButton(onClick = { TunnelLogBuffer.clear(sources[tabIndex]) }) {
                Icon(Icons.Filled.Delete, contentDescription = null)
                Text("Clear", modifier = Modifier.padding(start = 6.dp))
            }
            OutlinedButton(onClick = { TunnelLogBuffer.clearAll() }) {
                Icon(Icons.Filled.DeleteSweep, contentDescription = null)
                Text("Clear all", modifier = Modifier.padding(start = 6.dp))
            }
            OutlinedButton(
                onClick = {
                    shareLogs(context, TunnelLogBuffer.exportText(sources[tabIndex]), sources[tabIndex].name)
                },
            ) {
                Icon(Icons.AutoMirrored.Filled.Send, contentDescription = null)
                Text("Export tab", modifier = Modifier.padding(start = 6.dp))
            }
            OutlinedButton(
                onClick = {
                    shareLogs(context, TunnelLogBuffer.exportText(null), "all")
                },
            ) {
                Icon(Icons.AutoMirrored.Filled.Send, contentDescription = null)
                Text("Export all", modifier = Modifier.padding(start = 6.dp))
            }
        }
        LogList(lines = lines)
    }
}

private fun shareLogs(context: android.content.Context, text: String, label: String) {
    runCatching {
        val dir = File(context.cacheDir, "log-export").apply { mkdirs() }
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        val file = File(dir, "onionvpn-logs-$label-$stamp.txt")
        file.writeText(text)
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file,
        )
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "OnionVPN logs ($label)")
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_TEXT, text.take(8_000))
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, "Export OnionVPN logs"))
    }.onFailure { Timber.w(it, "Log export failed") }
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
        SimpleDateFormat("HH:mm:ss", Locale.getDefault())
    }
    Surface(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 12.dp, vertical = 4.dp),
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        LazyColumn(
            state = listState,
            modifier = Modifier
                .fillMaxSize()
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            items(lines) { line ->
                Text(
                    text = "${formatter.format(Date(line.timestampMs))}  ${line.level.exportMark}  ${line.text}",
                    style = MaterialTheme.typography.bodySmall,
                    color = logColor(line.severity),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

@Composable
private fun logColor(severity: StabilitySeverity): Color {
    val scheme = MaterialTheme.colorScheme
    return when (severity) {
        StabilitySeverity.CRITICAL, StabilitySeverity.ERROR -> scheme.error
        StabilitySeverity.WARN -> scheme.tertiary
        StabilitySeverity.INFO -> scheme.onSurface
        StabilitySeverity.DEBUG, StabilitySeverity.TRACE, StabilitySeverity.IGNORE ->
            scheme.onSurfaceVariant.copy(alpha = 0.75f)
    }
}
