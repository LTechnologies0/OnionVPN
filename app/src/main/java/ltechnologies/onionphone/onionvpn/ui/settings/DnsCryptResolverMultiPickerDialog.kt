package ltechnologies.onionphone.onionvpn.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import ltechnologies.onionphone.onionvpn.core.dnscrypt.config.DnsCryptPublicResolvers

@Composable
fun DnsCryptResolverMultiPickerDialog(
    selectedRaw: String,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    val initial = remember(selectedRaw) {
        DnsCryptPublicResolvers.resolveNames(selectedRaw).toSet()
    }
    var auto by remember {
        mutableStateOf(initial.size == 1 && initial.contains(DnsCryptPublicResolvers.AUTO))
    }
    var selected by remember {
        mutableStateOf(if (auto) emptySet() else initial.filter { it != DnsCryptPublicResolvers.AUTO }.toSet())
    }
    var query by remember { mutableStateOf("") }
    val resolvers = remember { DnsCryptPublicResolvers.all.filterNot { it.ipv6 } }
    val filtered = remember(query) {
        val q = query.trim()
        if (q.isEmpty()) {
            resolvers
        } else {
            resolvers.filter {
                it.name.contains(q, ignoreCase = true) ||
                    it.description.contains(q, ignoreCase = true)
            }
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("DNSCrypt resolvers (${resolvers.size})") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    label = { Text("Search") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                Text(
                    text = if (auto) {
                        "Auto — every resolver matching no-log / DNSSEC / filter prefs"
                    } else {
                        "${selected.size} selected · ${filtered.size} shown"
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                LazyColumn(modifier = Modifier.heightIn(max = 420.dp)) {
                    item {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .toggleable(
                                    value = auto,
                                    role = Role.Checkbox,
                                    onValueChange = {
                                        auto = it
                                        if (it) selected = emptySet()
                                    },
                                )
                                .padding(vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Checkbox(checked = auto, onCheckedChange = null)
                            Column(Modifier.padding(start = 8.dp)) {
                                Text("Auto (all matching filters)", style = MaterialTheme.typography.bodyLarge)
                                Text(
                                    "Omit server_names — rely on require_* flags",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                    items(filtered, key = { it.name }) { entry ->
                        val on = !auto && entry.name in selected
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .toggleable(
                                    value = on,
                                    role = Role.Checkbox,
                                    onValueChange = { checked ->
                                        auto = false
                                        selected = selected.toMutableSet().also { set ->
                                            if (checked) set.add(entry.name) else set.remove(entry.name)
                                        }
                                    },
                                )
                                .padding(vertical = 6.dp),
                            verticalAlignment = Alignment.Top,
                        ) {
                            Checkbox(checked = on, onCheckedChange = null)
                            Column(Modifier.padding(start = 8.dp)) {
                                Text(entry.name, style = MaterialTheme.typography.bodyLarge)
                                if (entry.description.isNotBlank()) {
                                    Text(
                                        entry.description,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 3,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val encoded = if (auto || selected.isEmpty()) {
                        DnsCryptPublicResolvers.AUTO
                    } else {
                        DnsCryptPublicResolvers.encodeNames(selected)
                    }
                    onConfirm(encoded)
                },
            ) { Text("Apply") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}
