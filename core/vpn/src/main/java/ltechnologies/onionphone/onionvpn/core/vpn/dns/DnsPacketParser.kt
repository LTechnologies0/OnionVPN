package ltechnologies.onionphone.onionvpn.core.vpn.dns

import ltechnologies.onionphone.onionvpn.core.model.TorNetPolicy

/**
 * Minimal DNS message parser for firewall hostname attribution and torrified DNS mux.
 *
 * Extracts the first question QNAME and A/AAAA answer RDATA addresses.
 * Rejects oversize QDCOUNT and invalid QNAME/address records (fail-closed).
 */
object DnsPacketParser {
    data class ParsedDns(
        val queryId: Int,
        val isResponse: Boolean,
        val qname: String?,
        val aRecords: List<String>,
    )

    fun parse(dns: ByteArray, offset: Int, length: Int): ParsedDns? {
        if (length < 12 || offset < 0 || offset + length > dns.size) return null
        val id = ((dns[offset].toInt() and 0xff) shl 8) or (dns[offset + 1].toInt() and 0xff)
        val flags = ((dns[offset + 2].toInt() and 0xff) shl 8) or (dns[offset + 3].toInt() and 0xff)
        val isResponse = (flags and 0x8000) != 0
        val qdCount = ((dns[offset + 4].toInt() and 0xff) shl 8) or (dns[offset + 5].toInt() and 0xff)
        val anCount = ((dns[offset + 6].toInt() and 0xff) shl 8) or (dns[offset + 7].toInt() and 0xff)
        if (qdCount > TorNetPolicy.MAX_DNS_QDCOUNT) return null
        var pos = offset + 12
        val end = offset + length

        var qname: String? = null
        if (qdCount > 0) {
            val name = readName(dns, offset, pos, end) ?: return ParsedDns(id, isResponse, null, emptyList())
            qname = when {
                name.first.isEmpty() -> ""
                TorNetPolicy.isValidDnsHostname(name.first) -> name.first
                else -> return null
            }
            pos = name.second
            // QTYPE + QCLASS
            if (pos + 4 > end) return ParsedDns(id, isResponse, qname, emptyList())
            pos += 4
            // Skip remaining questions
            for (i in 1 until qdCount) {
                val skip = readName(dns, offset, pos, end) ?: break
                pos = skip.second + 4
                if (pos > end) break
            }
        }

        // Always harvest A/AAAA from answers when present — QNAME may be absent/compressed
        // oddly in some resolver replies; callers attribute via pending QNAME or query context.
        val answers = ArrayList<String>(minOf(anCount, TorNetPolicy.MAX_DNS_ANSWERS))
        if (isResponse && anCount > 0) {
            val limit = minOf(anCount, TorNetPolicy.MAX_DNS_ANSWERS)
            for (i in 0 until limit) {
                if (pos >= end) break
                val nameSkip = readName(dns, offset, pos, end) ?: break
                pos = nameSkip.second
                if (pos + 10 > end) break
                val type = ((dns[pos].toInt() and 0xff) shl 8) or (dns[pos + 1].toInt() and 0xff)
                val rdLength = ((dns[pos + 8].toInt() and 0xff) shl 8) or (dns[pos + 9].toInt() and 0xff)
                pos += 10
                if (pos + rdLength > end) break
                if (type == TYPE_A && rdLength == 4) {
                    val ip =
                        "${dns[pos].toInt() and 0xff}." +
                            "${dns[pos + 1].toInt() and 0xff}." +
                            "${dns[pos + 2].toInt() and 0xff}." +
                            "${dns[pos + 3].toInt() and 0xff}"
                    if (TorNetPolicy.isValidDnsAddressRecord(ip)) answers.add(ip)
                } else if (type == TYPE_AAAA && rdLength == 16) {
                    runCatching {
                        java.net.InetAddress.getByAddress(
                            dns.copyOfRange(pos, pos + 16),
                        ).hostAddress?.substringBefore('%')
                    }.getOrNull()?.let { addr ->
                        if (TorNetPolicy.isValidDnsAddressRecord(addr)) answers.add(addr)
                    }
                }
                pos += rdLength
            }
        }
        return ParsedDns(id, isResponse, qname, answers)
    }

    /**
     * @return Pair(name, nextOffset) or null on truncation / bad compression
     */
    private fun readName(
        dns: ByteArray,
        msgOffset: Int,
        start: Int,
        end: Int,
    ): Pair<String, Int>? {
        val labels = ArrayList<String>(6)
        var pos = start
        var jumped = false
        var next = start
        var jumps = 0
        var totalLabelBytes = 0
        while (pos < end) {
            val len = dns[pos].toInt() and 0xff
            when {
                len == 0 -> {
                    if (!jumped) next = pos + 1
                    break
                }
                (len and 0xc0) == 0xc0 -> {
                    if (pos + 1 >= end) return null
                    val ptr = ((len and 0x3f) shl 8) or (dns[pos + 1].toInt() and 0xff)
                    if (!jumped) next = pos + 2
                    pos = msgOffset + ptr
                    jumped = true
                    if (++jumps > 16) return null
                    if (pos < msgOffset || pos >= end) return null
                    continue
                }
                (len and 0xc0) != 0 -> return null
                else -> {
                    if (len > TorNetPolicy.MAX_LABEL_LEN) return null
                    if (pos + 1 + len > end) return null
                    totalLabelBytes += len + 1
                    if (totalLabelBytes > TorNetPolicy.MAX_HOSTNAME_LEN + 1) return null
                    for (i in 1..len) {
                        val ch = dns[pos + i].toInt() and 0xff
                        if (ch == 0 || ch > 0x7f) return null
                    }
                    labels.add(String(dns, pos + 1, len, Charsets.US_ASCII))
                    pos += 1 + len
                    if (!jumped) next = pos
                }
            }
        }
        if (labels.isEmpty()) return "" to next
        return labels.joinToString(".") to next
    }

    private const val TYPE_A = 1
    private const val TYPE_AAAA = 28
}
