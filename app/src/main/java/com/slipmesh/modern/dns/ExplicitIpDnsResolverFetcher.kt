package com.slipmesh.modern.dns

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.SecureRandom

interface DnsWireExchanger {
    @Throws(IOException::class)
    fun udp(endpoint: LiteralDnsEndpoint, query: ByteArray, timeoutMs: Int, maxResponseBytes: Int): ByteArray

    @Throws(IOException::class)
    fun tcp(endpoint: LiteralDnsEndpoint, query: ByteArray, timeoutMs: Int, maxResponseBytes: Int): ByteArray
}

class JvmDnsWireExchanger : DnsWireExchanger {
    override fun udp(endpoint: LiteralDnsEndpoint, query: ByteArray, timeoutMs: Int, maxResponseBytes: Int): ByteArray {
        DatagramSocket().use { socket ->
            socket.soTimeout = timeoutMs
            val target = InetSocketAddress(endpoint.inetAddress(), endpoint.port)
            socket.send(DatagramPacket(query, query.size, target))
            val buffer = ByteArray(maxResponseBytes)
            val reply = DatagramPacket(buffer, buffer.size)
            socket.receive(reply)
            if (reply.address != target.address || reply.port != target.port) throw IOException("DNS UDP source mismatch")
            return buffer.copyOf(reply.length)
        }
    }

    override fun tcp(endpoint: LiteralDnsEndpoint, query: ByteArray, timeoutMs: Int, maxResponseBytes: Int): ByteArray {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(endpoint.inetAddress(), endpoint.port), timeoutMs)
            socket.soTimeout = timeoutMs
            DataOutputStream(socket.getOutputStream()).use { output ->
                output.writeShort(query.size)
                output.write(query)
                output.flush()
                val input = DataInputStream(socket.getInputStream())
                val length = input.readUnsignedShort()
                if (length <= 0 || length > maxResponseBytes) throw IOException("DNS TCP response size invalid")
                return ByteArray(length).also(input::readFully)
            }
        }
    }
}

class ExplicitIpDnsResolverFetcher(
    private val endpoints: LiteralDnsEndpointRegistry,
    private val exchanger: DnsWireExchanger = JvmDnsWireExchanger(),
    private val timeoutMs: Int = 3_000,
    private val maxResponseBytes: Int = 65_535,
    private val transactionIdSource: () -> Int = { SecureRandom().nextInt(0x10000) },
) : EchResolverFetcher {
    init {
        require(timeoutMs > 0)
        require(maxResponseBytes in 512..65_535)
    }

    override fun fetch(source: EchResolverSource, hostname: String): EchResolverFetchResult {
        val endpoint = endpoints.find(source.sourceId) ?: return EchResolverFetchResult.Failed(EchResolverFetchFailure.UNAVAILABLE)
        return try {
            val id = transactionIdSource()
            if (id !in 0..0xFFFF) return EchResolverFetchResult.Failed(EchResolverFetchFailure.UNKNOWN)
            val query = DnsHttpsQueryCodec.buildQuery(hostname, id)
            val udp = exchanger.udp(endpoint, query, timeoutMs, maxResponseBytes)
            val udpValidation = DnsHttpsQueryCodec.validateResponse(udp, id, hostname)
                ?: return EchResolverFetchResult.Failed(EchResolverFetchFailure.IO_FAILURE)
            if (!udpValidation.truncated) {
                EchResolverFetchResult.Response(udp)
            } else {
                val tcp = exchanger.tcp(endpoint, query, timeoutMs, maxResponseBytes)
                val tcpValidation = DnsHttpsQueryCodec.validateResponse(tcp, id, hostname)
                    ?: return EchResolverFetchResult.Failed(EchResolverFetchFailure.IO_FAILURE)
                if (tcpValidation.truncated) EchResolverFetchResult.Failed(EchResolverFetchFailure.IO_FAILURE)
                else EchResolverFetchResult.Response(tcp)
            }
        } catch (_: SocketTimeoutException) {
            EchResolverFetchResult.Failed(EchResolverFetchFailure.TIMEOUT)
        } catch (_: IOException) {
            EchResolverFetchResult.Failed(EchResolverFetchFailure.IO_FAILURE)
        } catch (_: IllegalArgumentException) {
            EchResolverFetchResult.Failed(EchResolverFetchFailure.UNKNOWN)
        } catch (_: RuntimeException) {
            EchResolverFetchResult.Failed(EchResolverFetchFailure.UNKNOWN)
        }
    }
}
