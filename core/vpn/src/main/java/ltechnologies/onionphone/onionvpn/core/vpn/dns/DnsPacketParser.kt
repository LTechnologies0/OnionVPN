package ltechnologies.onionphone.onionvpn.core.vpn.dns

/**
 * Minimal DNS message parser for firewall hostname attribution.
 *
 * Extracts the first question QNAME and A (type 1) answer RDATA IPv4 addresses.
 * Does not allocate during failure paths beyond the returned lists.
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
        var pos = offset + 12
        val end = offset + length

        var qname: String? = null
        if (qdCount > 0) {
            val name = readName(dns, offset, pos, end) ?: return ParsedDns(id, isResponse, null, emptyList())
            qname = name.first
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

        val answers = ArrayList<String>(minOf(anCount, 8))
        if (isResponse && anCount > 0 && qname != null) {
            for (i in 0 until anCount) {
                if (pos >= end) break
                val nameSkip = readName(dns, offset, pos, end) ?: break
                pos = nameSkip.second
                if (pos + 10 > end) break
                val type = ((dns[pos].toInt() and 0xff) shl 8) or (dns[pos + 1].toInt() and 0xff)
                // class at pos+2, ttl at pos+4
                val rdLength = ((dns[pos + 8].toInt() and 0xff) shl 8) or (dns[pos + 9].toInt() and 0xff)
                pos += 10
                if (pos + rdLength > end) break
                if (type == TYPE_A && rdLength == 4) {
                    answers.add(
                        "${dns[pos].toInt() and 0xff}." +
                            "${dns[pos + 1].toInt() and 0xff}." +
                            "${dns[pos + 2].toInt() and 0xff}." +
                            "${dns[pos + 3].toInt() and 0xff}",
                    )
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
                else -> {
                    if (pos + 1 + len > end) return null
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
}
