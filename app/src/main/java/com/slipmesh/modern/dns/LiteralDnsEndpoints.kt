package com.slipmesh.modern.dns

import java.net.InetAddress

data class LiteralDnsEndpoint(
    val sourceId: String,
    val address: String,
    val port: Int = 53,
) {
    private val addressBytes: ByteArray = parseIpv4Literal(address)

    init {
        require(sourceId.isNotBlank())
        require(port in 1..65535)
    }

    internal fun inetAddress(): InetAddress = InetAddress.getByAddress(addressBytes.copyOf())

    companion object {
        internal fun parseIpv4Literal(value: String): ByteArray {
            require(value.isNotBlank() && value == value.trim()) { "literal resolver address required" }
            val parts = value.split('.')
            require(parts.size == 4) { "only literal IPv4 resolver endpoints are qualified" }
            return ByteArray(4) { index ->
                val part = parts[index]
                require(part.isNotEmpty() && part.all(Char::isDigit)) { "invalid IPv4 literal" }
                val octet = part.toIntOrNull() ?: throw IllegalArgumentException("invalid IPv4 literal")
                require(octet in 0..255) { "invalid IPv4 literal" }
                octet.toByte()
            }
        }
    }
}

class LiteralDnsEndpointRegistry(endpoints: Collection<LiteralDnsEndpoint>) {
    private val bySourceId: Map<String, LiteralDnsEndpoint>

    init {
        require(endpoints.map { it.sourceId }.distinct().size == endpoints.size) {
            "resolver endpoint source ids must be unique"
        }
        bySourceId = endpoints.associateBy { it.sourceId }
    }

    fun find(sourceId: String): LiteralDnsEndpoint? = bySourceId[sourceId]
}
