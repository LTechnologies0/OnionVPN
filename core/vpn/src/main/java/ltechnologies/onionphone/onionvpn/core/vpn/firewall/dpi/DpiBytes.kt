package ltechnologies.onionphone.onionvpn.core.vpn.firewall.dpi

import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketInfo

/** Nested DPI byte helpers (transport offset + ASCII scans). */
internal object DpiBytes {
    fun transportPayloadOffset(
        packet: ByteArray,
        length: Int,
        info: IpPacketInfo,
    ): Int? {
        if (length < 20) return null
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (ihl < 20 || length < ihl) return null
        return when {
            info.isTcp -> {
                if (length < ihl + 20) return null
                val dataOff = ((packet[ihl + 12].toInt() and 0xff) ushr 4) * 4
                if (dataOff < 20) return null
                val off = ihl + dataOff
                if (off > length) null else off
            }
            info.isUdp -> {
                val off = ihl + 8
                if (off > length) null else off
            }
            else -> null
        }
    }

    fun startsWithAscii(packet: ByteArray, offset: Int, len: Int, prefix: String): Boolean {
        if (len < prefix.length) return false
        for (i in prefix.indices) {
            if ((packet[offset + i].toInt() and 0xff).toChar() != prefix[i]) return false
        }
        return true
    }

    fun asciiPrefix(packet: ByteArray, offset: Int, len: Int, max: Int): String? {
        val n = minOf(len, max)
        if (n <= 0) return null
        val sb = StringBuilder(n)
        for (i in 0 until n) {
            val c = packet[offset + i].toInt() and 0xff
            if (c == 0 || c == '\r'.code || c == '\n'.code) break
            if (c in 32..126) sb.append(c.toChar()) else break
        }
        return sb.toString().takeIf { it.isNotBlank() }
    }

    fun asciiContains(packet: ByteArray, offset: Int, len: Int, needle: String): Boolean {
        if (len < needle.length) return false
        outer@ for (i in 0..len - needle.length) {
            for (j in needle.indices) {
                if ((packet[offset + i + j].toInt() and 0xff).toChar() != needle[j]) continue@outer
            }
            return true
        }
        return false
    }

    /** IMAP tagged command: `a001 LOGIN …` */
    fun asciiStartsWithTagCommand(
        packet: ByteArray,
        offset: Int,
        len: Int,
        command: String,
    ): Boolean {
        if (len < command.length + 2) return false
        var i = 0
        while (i < len && i < 16) {
            val c = packet[offset + i].toInt() and 0xff
            if (c == ' '.code) {
                return startsWithAscii(packet, offset + i + 1, len - i - 1, "$command ") ||
                    startsWithAscii(packet, offset + i + 1, len - i - 1, command)
            }
            if (c !in 'A'.code..'Z'.code && c !in 'a'.code..'z'.code &&
                c !in '0'.code..'9'.code && c != '.'.code
            ) {
                return false
            }
            i++
        }
        return false
    }

    fun u16(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)

}
