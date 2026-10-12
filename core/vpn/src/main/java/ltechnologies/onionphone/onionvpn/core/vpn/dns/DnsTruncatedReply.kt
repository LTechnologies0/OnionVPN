package ltechnologies.onionphone.onionvpn.core.vpn.dns

/**
 * Header-only DNS response with the TC (truncated) bit set.
 *
 * Used when a UDP reply would exceed TUN MTU: RFC 1035 clients retry over TCP.
 */
object DnsTruncatedReply {
    /** QR | TC | RA, plus OPCODE/RD copied from the query flags word. */
    fun headerOnly(queryId: Int, queryFlags: Int = 0x0100): ByteArray {
        val id = queryId and 0xffff
        val opcode = queryFlags and 0x7800
        val rd = queryFlags and 0x0100
        val flags = 0x8000 or opcode or 0x0200 or rd or 0x0080
        return byteArrayOf(
            (id ushr 8).toByte(),
            id.toByte(),
            (flags ushr 8).toByte(),
            flags.toByte(),
            0, 0, // QDCOUNT
            0, 0, // ANCOUNT
            0, 0, // NSCOUNT
            0, 0, // ARCOUNT
        )
    }

    fun isTruncated(dns: ByteArray, length: Int = dns.size): Boolean {
        if (length < 4) return false
        val flags = ((dns[2].toInt() and 0xff) shl 8) or (dns[3].toInt() and 0xff)
        return (flags and 0x0200) != 0 && (flags and 0x8000) != 0
    }
}
