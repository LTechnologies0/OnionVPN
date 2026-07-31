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

@Composable
fun TorNodePickerDialog(
    title: String,
    initialRaw: String,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var selected by remember {
        mutableStateOf(TorCountryCatalog.parseNodeCodes(initialRaw).toMutableSet())
    }
    var query by remember { mutableStateOf("") }
    val countries = remember { TorCountryCatalog.countries }
    val filtered = remember(query) {
        val q = query.trim()
        if (q.isEmpty()) {
            countries
        } else {
            countries.filter {
                it.code.contains(q, ignoreCase = true) ||
                    it.name.contains(q, ignoreCase = true)
            }
        }
    }

    fun toggle(code: String, on: Boolean) {
        selected = selected.toMutableSet().also { set ->
            if (on) set.add(code) else set.remove(code)
        }
    }

    fun applyFederation(codes: Set<String>, add: Boolean) {
        selected = selected.toMutableSet().also { set ->
            if (add) set.addAll(codes) else set.removeAll(codes)
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "Tor country codes → ${TorCountryCatalog.encodeNodeCodes(selected).ifBlank { "(empty)" }}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    label = { Text("Search countries") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                LazyColumn(modifier = Modifier.heightIn(max = 420.dp)) {
                    item {
                        Text(
                            "Federations",
                            style = MaterialTheme.typography.titleSmall,
                            modifier = Modifier.padding(vertical = 6.dp),
                        )
                    }
                    items(TorCountryCatalog.federations, key = { it.id }) { fed ->
                        val allOn = fed.codes.all { it in selected }
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .toggleable(
                                    value = allOn,
                                    role = Role.Checkbox,
                                    onValueChange = { applyFederation(fed.codes, it) },
                                )
                                .padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Checkbox(checked = allOn, onCheckedChange = null)
                            Column(modifier = Modifier.padding(start = 8.dp)) {
                                Text(fed.label, style = MaterialTheme.typography.bodyLarge)
                                Text(
                                    fed.description,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                    item {
                        Text(
                            "Countries (${filtered.size})",
                            style = MaterialTheme.typography.titleSmall,
                            modifier = Modifier.padding(top = 8.dp, bottom = 6.dp),
                        )
                    }
                    items(filtered, key = { it.code }) { country ->
                        val on = country.code in selected
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .toggleable(
                                    value = on,
                                    role = Role.Checkbox,
                                    onValueChange = { toggle(country.code, it) },
                                )
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Checkbox(checked = on, onCheckedChange = null)
                            Text(
                                text = country.label,
                                style = MaterialTheme.typography.bodyLarge,
                                modifier = Modifier.padding(start = 8.dp),
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(TorCountryCatalog.encodeNodeCodes(selected)) }) {
                Text("Apply")
            }
        },
        dismissButton = {
            Row {
                TextButton(onClick = { selected = mutableSetOf() }) { Text("Clear") }
                TextButton(onClick = onDismiss) { Text("Cancel") }
            }
        },
    )
}
