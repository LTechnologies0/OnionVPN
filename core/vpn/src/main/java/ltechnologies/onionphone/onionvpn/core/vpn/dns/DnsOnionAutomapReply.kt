package ltechnologies.onionphone.onionvpn.core.vpn.dns

/**
 * Builds a minimal DNS response with a single A record for app-side Automap (Arti).
 *
 * Copies the question section from the query and appends one A RR pointing at [ipv4].
 */
object DnsOnionAutomapReply {
    /**
     * @param queryDns DNS payload (not including IP/UDP headers)
     * @param ipv4 dotted-quad in Tor Automap pool
     * @return full DNS response bytes, or null if the query is unusable
     */
    fun buildAResponse(queryDns: ByteArray, queryOffset: Int, queryLen: Int, ipv4: String): ByteArray? {
        if (queryLen < 12 || queryOffset < 0 || queryOffset + queryLen > queryDns.size) return null
        val octets = ipv4.split('.').mapNotNull { it.toIntOrNull()?.takeIf { v -> v in 0..255 } }
        if (octets.size != 4) return null

        // Find end of first question (QNAME + QTYPE + QCLASS).
        var pos = queryOffset + 12
        val end = queryOffset + queryLen
        while (pos < end) {
            val len = queryDns[pos].toInt() and 0xff
            when {
                len == 0 -> {
                    pos += 1
                    break
                }
                (len and 0xc0) == 0xc0 -> {
                    pos += 2
                    break
                }
                else -> {
                    pos += 1 + len
                    if (pos > end) return null
                }
            }
        }
        if (pos + 4 > end) return null
        val questionEnd = pos + 4
        val questionLen = questionEnd - queryOffset

        // Header (12) + question + answer (name ptr 2 + type/class/ttl/rdlen 10 + rdata 4)
        val out = ByteArray(questionLen + 16)
        System.arraycopy(queryDns, queryOffset, out, 0, questionLen)
        // Flags: QR|AA|RD, copy RD from query if set
        val queryFlags = ((queryDns[queryOffset + 2].toInt() and 0xff) shl 8) or
            (queryDns[queryOffset + 3].toInt() and 0xff)
        val rd = queryFlags and 0x0100
        val flags = 0x8400 or rd // QR + AA + RA-ish response
        out[2] = ((flags ushr 8) and 0xff).toByte()
        out[3] = (flags and 0xff).toByte()
        out[4] = 0
        out[5] = 1 // QDCOUNT
        out[6] = 0
        out[7] = 1 // ANCOUNT
        out[8] = 0
        out[9] = 0
        out[10] = 0
        out[11] = 0

        var w = questionLen
        // NAME = pointer to offset 12 (start of QNAME in this message)
        out[w++] = 0xc0.toByte()
        out[w++] = 0x0c
        out[w++] = 0
        out[w++] = 1 // TYPE A
        out[w++] = 0
        out[w++] = 1 // CLASS IN
        out[w++] = 0
        out[w++] = 0
        out[w++] = 0
        out[w++] = 60 // TTL 60s
        out[w++] = 0
        out[w++] = 4 // RDLENGTH
        out[w++] = octets[0].toByte()
        out[w++] = octets[1].toByte()
        out[w++] = octets[2].toByte()
        out[w++] = octets[3].toByte()
        return out
    }
}
