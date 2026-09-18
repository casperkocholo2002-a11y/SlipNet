package app.slipnet.tunnel

import com.slipmesh.modern.dns.DnsHttpsQueryCodec
import com.slipmesh.modern.dns.EchResolverFetchFailure
import com.slipmesh.modern.dns.EchResolverFetchResult
import com.slipmesh.modern.dns.EchResolverFetcher
import com.slipmesh.modern.dns.EchResolverSource
import com.slipmesh.modern.dns.LiteralDnsEndpoint
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.SecureRandom
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager

data class LiteralDohEndpoint(
    val sourceId: String,
    val address: String,
    val tlsServerName: String,
    val port: Int = 443,
    val path: String = "/dns-query",
) {
    val literalDnsEndpoint = LiteralDnsEndpoint(sourceId, address, port)

    init {
        require(tlsServerName.isNotBlank())
        require(path.startsWith('/'))
    }
}

class LiteralDohEndpointRegistry(endpoints: Collection<LiteralDohEndpoint>) {
    private val bySourceId: Map<String, LiteralDohEndpoint>

    init {
        require(endpoints.map { it.sourceId }.distinct().size == endpoints.size)
        bySourceId = endpoints.associateBy { it.sourceId }
    }

    fun find(sourceId: String): LiteralDohEndpoint? = bySourceId[sourceId]
}

class LiteralIpDohEchResolverFetcher(
    private val endpoints: LiteralDohEndpointRegistry,
    private val timeoutMs: Int = 4_000,
    private val maxResponseBytes: Int = 65_535,
    private val transactionIdSource: () -> Int = { SecureRandom().nextInt(0x10000) },
) : EchResolverFetcher {
    init {
        require(timeoutMs > 0)
        require(maxResponseBytes in 512..65_535)
    }

    override fun fetch(source: EchResolverSource, hostname: String): EchResolverFetchResult {
        val endpoint = endpoints.find(source.sourceId)
            ?: return EchResolverFetchResult.Failed(EchResolverFetchFailure.UNAVAILABLE)
        return try {
            val id = transactionIdSource()
            if (id !in 0..0xFFFF) return EchResolverFetchResult.Failed(EchResolverFetchFailure.UNKNOWN)
            val query = DnsHttpsQueryCodec.buildQuery(hostname, id)
            val packet = postDnsMessage(endpoint, query)
            val valid = DnsHttpsQueryCodec.validateResponse(packet, id, hostname)
                ?: return EchResolverFetchResult.Failed(EchResolverFetchFailure.IO_FAILURE)
            if (valid.truncated) EchResolverFetchResult.Failed(EchResolverFetchFailure.IO_FAILURE)
            else EchResolverFetchResult.Response(packet)
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

    private fun postDnsMessage(endpoint: LiteralDohEndpoint, query: ByteArray): ByteArray {
        val raw = Socket()
        raw.connect(InetSocketAddress(endpoint.literalDnsEndpoint.inetAddress(), endpoint.port), timeoutMs)
        raw.soTimeout = timeoutMs
        val context = SSLContext.getInstance("TLS")
        context.init(null, arrayOf<TrustManager>(TlsIdentity.systemTrustManager()), null)
        val ssl = context.socketFactory.createSocket(
            raw,
            endpoint.tlsServerName,
            endpoint.port,
            true,
        ) as SSLSocket
        return ssl.use { socket ->
            socket.soTimeout = timeoutMs
            TlsIdentity.configure(socket, endpoint.tlsServerName)
            socket.startHandshake()
            TlsIdentity.verify(socket, endpoint.tlsServerName)
            val header = buildString {
                append("POST ${endpoint.path} HTTP/1.1\r\n")
                append("Host: ${endpoint.tlsServerName}\r\n")
                append("Content-Type: application/dns-message\r\n")
                append("Accept: application/dns-message\r\n")
                append("Content-Length: ${query.size}\r\n")
                append("Connection: close\r\n\r\n")
            }.toByteArray(Charsets.US_ASCII)
            socket.outputStream.write(header)
            socket.outputStream.write(query)
            socket.outputStream.flush()
            val rawHttp = readBounded(socket, maxResponseBytes + 16_384)
            decodeDnsHttpResponse(rawHttp)
        }
    }

    private fun readBounded(socket: SSLSocket, limit: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (true) {
            val count = socket.inputStream.read(buffer)
            if (count < 0) break
            if (out.size() + count > limit) throw IOException("DoH response too large")
            out.write(buffer, 0, count)
        }
        return out.toByteArray()
    }

    private fun decodeDnsHttpResponse(raw: ByteArray): ByteArray {
        val separator = byteArrayOf(13, 10, 13, 10)
        val headerEnd = raw.indexOfSubsequence(separator)
        if (headerEnd < 0) throw IOException("malformed DoH HTTP response")
        val headerText = raw.copyOfRange(0, headerEnd).toString(Charsets.ISO_8859_1)
        val lines = headerText.split("\r\n")
        val status = lines.firstOrNull()?.split(' ')?.getOrNull(1)?.toIntOrNull()
        if (status != 200) throw IOException("DoH HTTP status $status")
        val headers = lines.drop(1).mapNotNull { line ->
            val colon = line.indexOf(':')
            if (colon <= 0) null else line.substring(0, colon).trim().lowercase() to line.substring(colon + 1).trim()
        }.toMap()
        val body = raw.copyOfRange(headerEnd + 4, raw.size)
        val decoded = when {
            headers["transfer-encoding"]?.contains("chunked", ignoreCase = true) == true -> decodeChunked(body)
            headers["content-length"] != null -> {
                val length = headers.getValue("content-length").toIntOrNull() ?: throw IOException("invalid DoH Content-Length")
                if (length < 0 || length > body.size) throw IOException("truncated DoH body")
                body.copyOfRange(0, length)
            }
            else -> body
        }
        if (decoded.isEmpty() || decoded.size > maxResponseBytes) throw IOException("invalid DoH DNS body size")
        return decoded
    }

    private fun decodeChunked(body: ByteArray): ByteArray {
        var cursor = 0
        val out = ByteArrayOutputStream()
        while (true) {
            val lineEnd = body.indexOfCrlf(cursor)
            if (lineEnd < 0) throw IOException("malformed chunk header")
            val sizeText = body.copyOfRange(cursor, lineEnd).toString(Charsets.US_ASCII).substringBefore(';').trim()
            val size = sizeText.toIntOrNull(16) ?: throw IOException("invalid chunk size")
            cursor = lineEnd + 2
            if (size == 0) break
            if (size < 0 || cursor + size + 2 > body.size) throw IOException("truncated chunk")
            if (out.size() + size > maxResponseBytes) throw IOException("DoH body too large")
            out.write(body, cursor, size)
            cursor += size
            if (body[cursor] != 13.toByte() || body[cursor + 1] != 10.toByte()) throw IOException("malformed chunk terminator")
            cursor += 2
        }
        return out.toByteArray()
    }

    private fun ByteArray.indexOfSubsequence(needle: ByteArray): Int {
        if (needle.isEmpty()) return 0
        for (start in 0..size - needle.size) {
            var match = true
            for (index in needle.indices) if (this[start + index] != needle[index]) { match = false; break }
            if (match) return start
        }
        return -1
    }

    private fun ByteArray.indexOfCrlf(start: Int): Int {
        var index = start
        while (index + 1 < size) {
            if (this[index] == 13.toByte() && this[index + 1] == 10.toByte()) return index
            index++
        }
        return -1
    }
}
