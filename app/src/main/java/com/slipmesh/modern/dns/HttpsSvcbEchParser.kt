package com.slipmesh.modern.dns

enum class EchDnsParseFailure {
    MALFORMED_PACKET,
    DNS_RCODE_FAILURE,
}

sealed interface EchDnsParseResult {
    data class Found(val echConfigList: ByteArray) : EchDnsParseResult {
        private val stored = echConfigList.copyOf()
        fun copyBytes(): ByteArray = stored.copyOf()
    }
    data object NoEch : EchDnsParseResult
    data class Rejected(val failure: EchDnsParseFailure, val rcode: Int? = null) : EchDnsParseResult
}

object HttpsSvcbEchParser {
    private const val DNS_HEADER_BYTES = 12
    private const val TYPE_HTTPS = 65
    private const val CLASS_IN = 1
    private const val PARAM_ECH = 5
    private const val MAX_PACKET_BYTES = 65535
    private const val MAX_ECH_BYTES = 8192

    fun parse(packet: ByteArray): EchDnsParseResult {
        if (packet.size !in DNS_HEADER_BYTES..MAX_PACKET_BYTES) return malformed()
        return try {
            val flags = u16(packet, 2)
            val rcode = flags and 0x0f
            if (rcode != 0) return EchDnsParseResult.Rejected(EchDnsParseFailure.DNS_RCODE_FAILURE, rcode)
            val qd = u16(packet, 4)
            val an = u16(packet, 6)
            var offset = DNS_HEADER_BYTES
            repeat(qd) {
                offset = skipName(packet, offset)
                requireRange(packet, offset, 4)
                offset += 4
            }
            repeat(an) {
                offset = skipName(packet, offset)
                requireRange(packet, offset, 10)
                val type = u16(packet, offset)
                val klass = u16(packet, offset + 2)
                val rdLength = u16(packet, offset + 8)
                val start = offset + 10
                val end = start + rdLength
                requireRange(packet, start, rdLength)
                if (type == TYPE_HTTPS && klass == CLASS_IN) {
                    val found = parseHttpsRdata(packet, start, end)
                    if (found != null) return EchDnsParseResult.Found(found)
                }
                offset = end
            }
            EchDnsParseResult.NoEch
        } catch (_: IllegalArgumentException) {
            malformed()
        } catch (_: IndexOutOfBoundsException) {
            malformed()
        }
    }

    private fun parseHttpsRdata(packet: ByteArray, start: Int, end: Int): ByteArray? {
        if (end - start < 3) throw IllegalArgumentException("truncated HTTPS RDATA")
        var cursor = start + 2
        cursor = skipName(packet, cursor)
        if (cursor > end) throw IllegalArgumentException("target exceeds RDATA")
        var previousKey = -1
        while (cursor < end) {
            if (end - cursor < 4) throw IllegalArgumentException("trailing SvcParam bytes")
            val key = u16(packet, cursor)
            val length = u16(packet, cursor + 2)
            if (key <= previousKey) throw IllegalArgumentException("SvcParam keys not strictly increasing")
            previousKey = key
            cursor += 4
            if (cursor + length > end) throw IllegalArgumentException("SvcParam exceeds RDATA")
            if (key == PARAM_ECH) {
                if (length !in 1..MAX_ECH_BYTES) throw IllegalArgumentException("invalid ECH size")
                return packet.copyOfRange(cursor, cursor + length)
            }
            cursor += length
        }
        if (cursor != end) throw IllegalArgumentException("RDATA trailing bytes")
        return null
    }

    private fun skipName(packet: ByteArray, start: Int): Int {
        var cursor = start
        var labels = 0
        while (true) {
            requireRange(packet, cursor, 1)
            val length = packet[cursor].toInt() and 0xff
            when {
                length == 0 -> return cursor + 1
                length and 0xc0 == 0xc0 -> {
                    requireRange(packet, cursor, 2)
                    val pointer = ((length and 0x3f) shl 8) or (packet[cursor + 1].toInt() and 0xff)
                    if (pointer >= packet.size) throw IllegalArgumentException("bad compression pointer")
                    return cursor + 2
                }
                length and 0xc0 != 0 -> throw IllegalArgumentException("bad DNS label")
                length > 63 -> throw IllegalArgumentException("label too long")
                else -> {
                    requireRange(packet, cursor + 1, length)
                    cursor += 1 + length
                    if (++labels > 127) throw IllegalArgumentException("too many labels")
                }
            }
        }
    }

    private fun u16(packet: ByteArray, offset: Int): Int {
        requireRange(packet, offset, 2)
        return ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)
    }

    private fun requireRange(packet: ByteArray, offset: Int, length: Int) {
        if (offset < 0 || length < 0 || offset > packet.size - length) throw IllegalArgumentException("truncated")
    }

    private fun malformed() = EchDnsParseResult.Rejected(EchDnsParseFailure.MALFORMED_PACKET)
}
