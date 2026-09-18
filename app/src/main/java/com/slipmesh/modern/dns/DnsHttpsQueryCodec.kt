package com.slipmesh.modern.dns

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

internal data class DnsResponseValidation(val truncated: Boolean)

internal object DnsHttpsQueryCodec {
    private const val TYPE_HTTPS = 65
    private const val CLASS_IN = 1
    private const val TYPE_OPT = 41
    const val DEFAULT_UDP_PAYLOAD_SIZE = 1232

    fun buildQuery(hostname: String, transactionId: Int, udpPayloadSize: Int = DEFAULT_UDP_PAYLOAD_SIZE): ByteArray {
        require(transactionId in 0..0xFFFF)
        require(udpPayloadSize in 512..4096)
        val labels = normalizedLabels(hostname)
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            data.writeShort(transactionId)
            data.writeShort(0x0100) // recursion desired
            data.writeShort(1) // QDCOUNT
            data.writeShort(0)
            data.writeShort(0)
            data.writeShort(1) // EDNS OPT
            writeName(data, labels)
            data.writeShort(TYPE_HTTPS)
            data.writeShort(CLASS_IN)
            data.writeByte(0) // OPT root name
            data.writeShort(TYPE_OPT)
            data.writeShort(udpPayloadSize)
            data.writeInt(0)
            data.writeShort(0)
        }
        return out.toByteArray()
    }

    fun validateResponse(packet: ByteArray, transactionId: Int, hostname: String): DnsResponseValidation? {
        if (packet.size < 12 || u16(packet, 0) != transactionId) return null
        val flags = u16(packet, 2)
        if (flags and 0x8000 == 0 || u16(packet, 4) != 1) return null
        var cursor = 12
        val name = readName(packet, cursor) ?: return null
        cursor = name.second
        if (!name.first.equals(normalizeHostname(hostname), ignoreCase = true)) return null
        if (cursor + 4 > packet.size) return null
        if (u16(packet, cursor) != TYPE_HTTPS || u16(packet, cursor + 2) != CLASS_IN) return null
        return DnsResponseValidation(truncated = flags and 0x0200 != 0)
    }

    private fun normalizedLabels(hostname: String): List<ByteArray> =
        normalizeHostname(hostname).split('.').map { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            require(bytes.isNotEmpty() && bytes.size <= 63 && label.all { it.code in 33..126 }) { "invalid DNS label" }
            bytes
        }.also { labels -> require(labels.sumOf { it.size + 1 } + 1 <= 255) }

    private fun normalizeHostname(hostname: String): String {
        val value = hostname.trimEnd('.')
        require(value.isNotBlank() && value == value.trim()) { "hostname required" }
        return value.lowercase()
    }

    private fun writeName(data: DataOutputStream, labels: List<ByteArray>) {
        for (label in labels) {
            data.writeByte(label.size)
            data.write(label)
        }
        data.writeByte(0)
    }

    private fun readName(packet: ByteArray, start: Int): Pair<String, Int>? {
        var cursor = start
        val labels = mutableListOf<String>()
        repeat(128) {
            if (cursor >= packet.size) return null
            val len = packet[cursor].toInt() and 0xFF
            if (len == 0) return labels.joinToString(".") to (cursor + 1)
            if (len and 0xC0 != 0 || len > 63 || cursor + 1 + len > packet.size) return null
            val bytes = packet.copyOfRange(cursor + 1, cursor + 1 + len)
            if (bytes.any { (it.toInt() and 0xFF) !in 33..126 }) return null
            labels += bytes.toString(Charsets.US_ASCII)
            cursor += 1 + len
        }
        return null
    }

    private fun u16(bytes: ByteArray, offset: Int): Int {
        if (offset < 0 || offset + 2 > bytes.size) return -1
        return ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
    }
}
