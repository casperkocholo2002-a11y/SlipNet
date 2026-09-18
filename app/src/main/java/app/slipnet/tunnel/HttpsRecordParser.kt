package app.slipnet.tunnel

internal object HttpsRecordParser {
    private const val DNS_TYPE_HTTPS = 65
    private const val DNS_CLASS_IN = 1
    private const val ECH_SVC_PARAM_KEY = 5

    fun extractEchConfigList(packet: ByteArray): ByteArray? {
        if (packet.size < 12) return null
        return try {
            val questionCount = u16(packet, 4)
            val answerCount = u16(packet, 6)
            var offset = 12

            repeat(questionCount) {
                offset = skipName(packet, offset)
                requireRange(packet, offset, 4)
                offset += 4
            }

            repeat(answerCount) {
                offset = skipName(packet, offset)
                requireRange(packet, offset, 10)
                val type = u16(packet, offset)
                val dnsClass = u16(packet, offset + 2)
                val rdLength = u16(packet, offset + 8)
                val rdataStart = offset + 10
                val rdataEnd = rdataStart + rdLength

                if (rdataEnd > packet.size) return null
                if (type == DNS_TYPE_HTTPS && dnsClass == DNS_CLASS_IN) {
                    parseHttpsRdata(packet, rdataStart, rdataEnd)?.let { return it }
                }
                offset = rdataEnd
            }
            null
        } catch (_: IllegalArgumentException) {
            null
        } catch (_: IndexOutOfBoundsException) {
            null
        }
    }

    private fun parseHttpsRdata(packet: ByteArray, start: Int, end: Int): ByteArray? {
        if (end - start < 3) return null
        var cursor = start + 2 // SvcPriority
        cursor = skipName(packet, cursor) // TargetName
        if (cursor > end) return null

        while (cursor < end) {
            if (end - cursor < 4) return null
            val key = u16(packet, cursor)
            val length = u16(packet, cursor + 2)
            cursor += 4
            if (cursor + length > end) return null
            if (key == ECH_SVC_PARAM_KEY) {
                return if (length > 0) packet.copyOfRange(cursor, cursor + length) else null
            }
            cursor += length
        }
        return null
    }

    private fun skipName(packet: ByteArray, start: Int): Int {
        var cursor = start
        var labels = 0
        while (true) {
            requireRange(packet, cursor, 1)
            val length = packet[cursor].toInt() and 0xFF
            when {
                length == 0 -> return cursor + 1
                length and 0xC0 == 0xC0 -> {
                    requireRange(packet, cursor, 2)
                    return cursor + 2
                }
                length and 0xC0 != 0 -> throw IllegalArgumentException("Invalid DNS label")
                length > 63 -> throw IllegalArgumentException("DNS label too long")
                else -> {
                    requireRange(packet, cursor + 1, length)
                    cursor += 1 + length
                    labels++
                    if (labels > 127) throw IllegalArgumentException("Too many DNS labels")
                }
            }
        }
    }

    private fun u16(packet: ByteArray, offset: Int): Int {
        requireRange(packet, offset, 2)
        return ((packet[offset].toInt() and 0xFF) shl 8) or
            (packet[offset + 1].toInt() and 0xFF)
    }

    private fun requireRange(packet: ByteArray, offset: Int, length: Int) {
        if (offset < 0 || length < 0 || offset + length > packet.size) {
            throw IllegalArgumentException("Truncated DNS packet")
        }
    }
}
