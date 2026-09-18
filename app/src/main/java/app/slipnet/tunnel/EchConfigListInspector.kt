package app.slipnet.tunnel

internal object EchConfigListInspector {
    private const val ECH_CONFIG_VERSION = 0xfe0d

    fun publicName(configList: ByteArray): String? {
        if (configList.size < 6) return null
        val listLength = u16(configList, 0) ?: return null
        if (listLength != configList.size - 2) return null
        val end = configList.size
        var cursor = 2
        var resolved: String? = null
        while (cursor < end) {
            if (cursor + 4 > end) return null
            val version = u16(configList, cursor) ?: return null
            val configLength = u16(configList, cursor + 2) ?: return null
            val bodyStart = cursor + 4
            val bodyEnd = bodyStart + configLength
            if (bodyEnd > end) return null
            if (version == ECH_CONFIG_VERSION) {
                val name = parsePublicName(configList, bodyStart, bodyEnd) ?: return null
                if (resolved != null && resolved != name) return null
                resolved = name
            }
            cursor = bodyEnd
        }
        return if (cursor == end) resolved else null
    }

    private fun parsePublicName(bytes: ByteArray, start: Int, end: Int): String? {
        var p = start
        if (p + 5 > end) return null
        p += 1 // config_id
        p += 2 // kem_id
        val keyLength = u16(bytes, p) ?: return null
        p += 2
        if (keyLength <= 0 || p + keyLength > end) return null
        p += keyLength
        if (p + 2 > end) return null
        val suitesLength = u16(bytes, p) ?: return null
        p += 2
        if (suitesLength <= 0 || suitesLength % 4 != 0 || p + suitesLength > end) return null
        p += suitesLength
        if (p + 2 > end) return null
        p += 1 // maximum_name_length
        val nameLength = bytes[p].toInt() and 0xff
        p += 1
        if (nameLength <= 0 || p + nameLength > end) return null
        val name = bytes.copyOfRange(p, p + nameLength).toString(Charsets.US_ASCII).lowercase()
        if (!validDnsName(name)) return null
        p += nameLength
        if (p + 2 > end) return null
        val extensionsLength = u16(bytes, p) ?: return null
        p += 2
        if (p + extensionsLength != end) return null
        return name
    }

    private fun validDnsName(name: String): Boolean {
        if (name.length !in 1..253 || name.startsWith('.') || name.endsWith('.')) return false
        return name.split('.').all { label ->
            label.length in 1..63 &&
                label.first().isLetterOrDigit() &&
                label.last().isLetterOrDigit() &&
                label.all { it.isLetterOrDigit() || it == '-' }
        }
    }

    private fun u16(bytes: ByteArray, offset: Int): Int? {
        if (offset < 0 || offset + 1 >= bytes.size) return null
        return ((bytes[offset].toInt() and 0xff) shl 8) or
            (bytes[offset + 1].toInt() and 0xff)
    }
}
