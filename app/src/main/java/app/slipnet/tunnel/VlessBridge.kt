package app.slipnet.tunnel

import android.os.SystemClock
import app.slipnet.BuildConfig
import app.slipnet.util.AppLog as Log
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Future
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

/**
 * VLESS tunnel bridge for Cloudflare CDN with SNI fragmentation.
 *
 * Provides a local SOCKS5 proxy that tunnels traffic through:
 *   App -> hev-socks5-tunnel -> VlessBridge SOCKS5 (listenPort)
 *     -> SniFragmentForwarder (listenPort+1) -> CDN IP:443
 *       -> TLS (fragmented ClientHello) -> WebSocket upgrade -> VLESS protocol
 *         -> Cloudflare CDN -> Your VLESS Server -> Internet
 *
 * VLESS protocol is extremely simple:
 * - Client sends: version(1) + UUID(16) + addons_len(1) + command(1) + port(2) + addr_type(1) + addr + payload
 * - Server responds: version(1) + addons_len(1) + raw data
 * - After the header exchange, it's raw bidirectional TCP data with no framing.
 */
object VlessBridge {
    private const val TAG = "VlessBridge"
    private const val BUFFER_SIZE = 65536
    private const val TCP_CONNECT_TIMEOUT_MS = 30000
    // Field data: healthy WS->VLESS establishment completed within ~6.1s at p100
    // during the upload regression. Bound the pre-session read so a half-dead
    // Cloudflare/Xray stream cannot pin a flow for 125-250 seconds.
    private const val VLESS_SESSION_ESTABLISHMENT_TIMEOUT_MS = 12_000
    private const val WARM_VLESS_RESPONSE_TIMEOUT_MS = 6_000
    private const val BIND_MAX_RETRIES = 10
    private const val BIND_RETRY_DELAY_MS = 200L

    // VLESS constants
    private const val VLESS_VERSION: Byte = 0x00
    private const val VLESS_CMD_TCP: Byte = 0x01
    private const val VLESS_ADDR_IPV4: Byte = 0x01
    private const val VLESS_ADDR_DOMAIN: Byte = 0x02
    private const val VLESS_ADDR_IPV6: Byte = 0x03

    var debugLogging = false
    private fun logd(msg: String) { if (debugLogging) Log.d(TAG, msg) }

    private var fragmentForwarder: SniFragmentForwarder? = null
    private var serverSocket: ServerSocket? = null
    private var acceptorThread: Thread? = null
    private val running = AtomicBoolean(false)
    private val connectionThreads = CopyOnWriteArrayList<Thread>()
    // Logical client/VPN boundary counters. These count each payload byte once when
    // it crosses the local SOCKS boundary, not each time transport retries/replays it.
    private val tunnelTxBytes = AtomicLong(0)
    private val tunnelRxBytes = AtomicLong(0)
    private val nextFlowId = AtomicLong(1)
    private val wsMaskScratch: ThreadLocal<ByteArray> = ThreadLocal.withInitial { ByteArray(BUFFER_SIZE) }

    private fun elapsedMs(startNs: Long): Long =
        (SystemClock.elapsedRealtimeNanos() - startNs).coerceAtLeast(0L) / 1_000_000L

    private data class WarmWsTunnel(
        val socket: Socket,
        val input: BufferedInputStream,
        val output: OutputStream,
        val createdAtNs: Long,
    )

    // The mandatory structural probe already pays TCP + ECH/TLS + WS upgrade.
    // Retain exactly that validated socket for the first real flow instead of throwing
    // the work away. No extra prewarming connection is created, so idle power stays low.
    private val warmWsTunnel = AtomicReference<WarmWsTunnel?>(null)
    private val warmRefillInFlight = AtomicBoolean(false)
    private val bridgeGeneration = AtomicLong(0)

    private fun closeWarmWsTunnel() {
        warmWsTunnel.getAndSet(null)?.let { warm ->
            try { warm.socket.close() } catch (_: Exception) {}
        }
    }

    private fun scheduleWarmWsRefill() {
        if (!BuildConfig.PERSONAL_BUILD || echMode != EchMode.REQUIRED || transport != "ws") return
        if (!running.get() || warmWsTunnel.get() != null) return
        if (!warmRefillInFlight.compareAndSet(false, true)) return
        val generation = bridgeGeneration.get()
        Thread({
            var candidate: WarmWsTunnel? = null
            try {
                val socket = connectUpstreamTunnel(10_000, 10_000)
                val input = BufferedInputStream(socket.getInputStream())
                val output = socket.getOutputStream()
                val wsKey = generateWsKey()
                output.write(buildWsUpgradeRequest(wsKey).toByteArray(Charsets.US_ASCII))
                output.flush()
                val statusLine = readLine(input) ?: throw Exception("No WS response")
                if ("101" !in statusLine) throw Exception("WS upgrade failed")
                while (true) { val line = readLine(input) ?: break; if (line.isEmpty()) break }
                socket.soTimeout = 0
                candidate = WarmWsTunnel(socket, input, output, SystemClock.elapsedRealtimeNanos())
                if (running.get() && generation == bridgeGeneration.get() && warmWsTunnel.compareAndSet(null, candidate)) {
                    candidate = null
                    Log.operational("WARM_WS_REFILLED")
                }
            } catch (_: Exception) {
                if (running.get() && generation == bridgeGeneration.get()) {
                    Log.operational("WARM_WS_REFILL_FAILED")
                }
            } finally {
                candidate?.let { try { it.socket.close() } catch (_: Exception) {} }
                warmRefillInFlight.set(false)
            }
        }, "vless-warm-refill").apply { isDaemon = true; start() }
    }

    // Configuration (set before start)
    private var cdnIp: String = ""
    private var cdnPort: Int = 443
    private var serverDomain: String = ""
    private var vlessUuid: String = ""
    private var security: String = "tls"
    private var transport: String = "ws"
    private var wsPath: String = "/"
    private var fragmentStrategy: String = "sni_split"
    private var fragmentDelayMs: Int = 100
    private var sniSpoofTtl: Int = 8
    private var fakeDecoyHost: String = ""
    private var tcpMaxSeg: Int = 0
    private var vlessSni: String = ""
    private var fragmentEnabled: Boolean = true
    private var chPaddingEnabled: Boolean = false
    private var wsHeaderObfuscation: Boolean = false
    private var wsPaddingEnabled: Boolean = false
    private var echMode: EchMode = EchMode.DISABLED
    @Volatile private var echConfigList: ByteArray? = null
    private var onAuthenticatedEchConfigAccepted: ((ByteArray) -> Unit)? = null
    private val random = SecureRandom()

    fun start(
        listenPort: Int,
        listenHost: String = "127.0.0.1",
        cdnIp: String,
        cdnPort: Int = 443,
        serverDomain: String,
        vlessUuid: String,
        security: String = "tls",
        transport: String = "ws",
        wsPath: String = "/",
        fragmentEnabled: Boolean = true,
        fragmentStrategy: String = "sni_split",
        fragmentDelayMs: Int = 100,
        sniSpoofTtl: Int = 8,
        fakeDecoyHost: String = "",
        tcpMaxSeg: Int = 0,
        vlessSni: String = "",
        chPaddingEnabled: Boolean = false,
        wsHeaderObfuscation: Boolean = false,
        wsPaddingEnabled: Boolean = false,
        echMode: EchMode = EchMode.DISABLED,
        echConfigList: ByteArray? = null,
        onAuthenticatedEchConfigAccepted: ((ByteArray) -> Unit)? = null,
    ): Result<Unit> {
        if (echMode != EchMode.DISABLED && security == "none") {
            return Result.failure(IllegalArgumentException("ECH requires TLS security"))
        }
        if (echMode != EchMode.DISABLED && fragmentEnabled) {
            return Result.failure(IllegalArgumentException("ECH and fragmentation must be separate routes"))
        }
        if (echMode == EchMode.REQUIRED && echConfigList?.isNotEmpty() != true) {
            return Result.failure(IllegalArgumentException("ECH_REQUIRED needs a non-empty config list"))
        }
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting VLESS Bridge")
        if (!BuildConfig.PERSONAL_BUILD) {
            Log.i(TAG, "  CDN: $cdnIp:$cdnPort")
            Log.i(TAG, "  Domain: $serverDomain")
            Log.i(TAG, "  UUID: ${vlessUuid.take(8)}...")
            if (transport == "ws") Log.i(TAG, "  WS Path: $wsPath")
            if (fragmentStrategy == "fake" && fakeDecoyHost.isNotBlank()) Log.i(TAG, "  Fake Decoy Host: $fakeDecoyHost")
            if (vlessSni.isNotBlank()) Log.i(TAG, "  TLS SNI: $vlessSni")
        } else {
            Log.i(TAG, "  Endpoint identity: [redacted-personal]")
        }
        Log.i(TAG, "  Security: $security")
        Log.i(TAG, "  Transport: $transport")
        Log.i(TAG, "  Fragment: $fragmentEnabled (strategy=$fragmentStrategy, delay=${fragmentDelayMs}ms, spoofTtl=$sniSpoofTtl)")
        Log.i(TAG, "  CH Padding: $chPaddingEnabled | WS Header Obfuscation: $wsHeaderObfuscation | WS Padding: $wsPaddingEnabled")
        Log.i(TAG, "  ECH: $echMode")
        Log.i(TAG, "  Listen: $listenHost:$listenPort")
        Log.i(TAG, "========================================")

        stop()

        this.cdnIp = cdnIp
        this.cdnPort = cdnPort
        this.serverDomain = serverDomain
        this.vlessUuid = vlessUuid
        this.security = security
        this.transport = transport
        this.wsPath = wsPath
        this.fragmentEnabled = fragmentEnabled
        this.fragmentStrategy = fragmentStrategy
        this.fragmentDelayMs = fragmentDelayMs
        this.sniSpoofTtl = sniSpoofTtl
        this.fakeDecoyHost = fakeDecoyHost
        this.tcpMaxSeg = tcpMaxSeg
        this.vlessSni = vlessSni
        this.chPaddingEnabled = chPaddingEnabled
        this.wsHeaderObfuscation = wsHeaderObfuscation
        this.wsPaddingEnabled = wsPaddingEnabled
        this.echMode = echMode
        this.echConfigList = echConfigList?.copyOf()
        this.onAuthenticatedEchConfigAccepted = onAuthenticatedEchConfigAccepted

        return try {
            // Step 1: Start fragment forwarder if enabled
            if (fragmentEnabled) {
                val fragmentPort = listenPort + 1
                fragmentForwarder = SniFragmentForwarder("vless").apply {
                    this.connectIp = cdnIp
                    this.connectPort = cdnPort
                    this.fragmentStrategy = fragmentStrategy
                    this.fragmentDelayMs = fragmentDelayMs
                    this.chPaddingEnabled = chPaddingEnabled
                    this.lowTtl = sniSpoofTtl
                    this.fakeDecoyHost = fakeDecoyHost
                    this.tcpMaxSeg = tcpMaxSeg
                    this.debugLogging = debugLogging
                }
                val fragResult = fragmentForwarder!!.start(fragmentPort, "127.0.0.1")
                if (fragResult.isFailure) {
                    return Result.failure(fragResult.exceptionOrNull()
                        ?: Exception("Failed to start fragment forwarder"))
                }
                Log.i(TAG, "Fragment forwarder started on port $fragmentPort")
            }

            // Step 2: Start SOCKS5 server
            val ss = bindServerSocket(listenHost, listenPort)
            serverSocket = ss
            running.set(true)

            acceptorThread = Thread({
                logd("SOCKS5 acceptor started")
                while (running.get() && !Thread.currentThread().isInterrupted) {
                    try {
                        val client = ss.accept()
                        val t = Thread({
                            handleSocks5Connection(client)
                        }, "vless-conn-${System.nanoTime()}")
                        t.isDaemon = true
                        connectionThreads.add(t)
                        t.start()
                    } catch (e: Exception) {
                        if (running.get()) Log.w(TAG, "Accept error: ${e.message}")
                    }
                }
                logd("SOCKS5 acceptor exited")
            }, "vless-acceptor")
            acceptorThread!!.isDaemon = true
            acceptorThread!!.start()

            Log.i(TAG, "VLESS Bridge started on $listenHost:$listenPort")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VLESS bridge: ${e.message}", e)
            stop()
            Result.failure(e)
        }
    }

    fun stop() {
        bridgeGeneration.incrementAndGet()
        closeWarmWsTunnel()
        if (!running.getAndSet(false) && fragmentForwarder == null) return
        Log.i(TAG, "Stopping VLESS Bridge")
        try { serverSocket?.close() } catch (_: Exception) {}
        acceptorThread?.interrupt()
        connectionThreads.forEach { it.interrupt() }
        connectionThreads.clear()
        fragmentForwarder?.stop()
        fragmentForwarder = null
        serverSocket = null
        acceptorThread = null
    }

    fun isRunning(): Boolean = running.get() && serverSocket?.isClosed == false
    fun isClientHealthy(): Boolean = isRunning()
    fun getTunnelTxBytes(): Long = tunnelTxBytes.get()
    fun getTunnelRxBytes(): Long = tunnelRxBytes.get()

    fun resetTrafficStats() {
        tunnelTxBytes.set(0)
        tunnelRxBytes.set(0)
    }

    private fun connectRawUpstream(readTimeoutMs: Int): Socket {
        val socket = Socket()
        val target = if (fragmentEnabled) {
            val fragmentPort = (serverSocket?.localPort ?: 0) + 1
            InetSocketAddress("127.0.0.1", fragmentPort)
        } else {
            InetSocketAddress(cdnIp, cdnPort)
        }
        socket.tcpNoDelay = true
        socket.connect(target, TCP_CONNECT_TIMEOUT_MS)
        socket.soTimeout = readTimeoutMs
        return socket
    }

    private fun connectUpstreamTunnel(
        handshakeTimeoutMs: Int,
        finalReadTimeoutMs: Int,
        telemetryFlowId: Long = 0L,
    ): Socket {
        if (security == "none") return connectRawUpstream(finalReadTimeoutMs)
        val serverName = resolveSni()
        if (echMode != EchMode.DISABLED) {
            if (telemetryFlowId > 0L) {
                Log.operational("ECH_REQUIRED_STARTED", "flow" to telemetryFlowId)
            }
            // Take an immutable snapshot so concurrent flows either use the previous
            // authenticated config or the newly accepted one, never a mutable shared array.
            val activeEchConfig = echConfigList?.copyOf()
            val request = EchConnectRequest(
                connectHost = cdnIp,
                port = cdnPort,
                serverName = serverName,
                configList = activeEchConfig,
                connectTimeoutMs = TCP_CONNECT_TIMEOUT_MS,
                readTimeoutMs = handshakeTimeoutMs,
                telemetryFlowId = telemetryFlowId,
            )
            val acceptedConfigCallback = onAuthenticatedEchConfigAccepted
            return when (val result = EchTlsCoordinator(
                backend = EchBackends.current(),
                onAuthenticatedRetryAccepted = { config ->
                    // Promote authenticated retry material to the live bridge immediately.
                    // Persistence is durable storage; this runtime update prevents every
                    // subsequent SOCKS flow from paying the stale-seed retry again.
                    val freshConfig = config.copyOf()
                    echConfigList = freshConfig
                    Log.operational("ECH_RUNTIME_SEED_UPDATED")
                    acceptedConfigCallback?.invoke(freshConfig.copyOf())
                },
            ).connect(echMode, request)) {
                is EchConnectResult.Connected -> result.socket.apply { soTimeout = finalReadTimeoutMs }
                is EchConnectResult.Failed -> throw result.error
                is EchConnectResult.Retry -> throw javax.net.ssl.SSLHandshakeException("Unexpected unconsumed ECH retry")
            }
        }

        val raw = connectRawUpstream(handshakeTimeoutMs)
        try {
            val context = SSLContext.getInstance("TLS")
            context.init(null, null, SecureRandom())
            val ssl = context.socketFactory.createSocket(raw, serverName, cdnPort, true) as SSLSocket
            TlsIdentity.configure(ssl, serverName)
            ssl.startHandshake()
            TlsIdentity.verify(ssl, serverName)
            ssl.soTimeout = finalReadTimeoutMs
            return ssl
        } catch (error: Throwable) {
            try { raw.close() } catch (_: Exception) {}
            throw error
        }
    }

    /**
     * Structural probe: verifies the parts of the connection that depend on
     * *your* config — TCP to the CDN, TLS (correct SNI), and the WebSocket
     * upgrade (correct WS path). Catches wrong `cdnIp`, wrong `serverDomain`,
     * wrong `wsPath`.
     *
     * Intentionally does NOT send a VLESS CONNECT with a destination: CF
     * Workers commonly filter outbound destinations (e.g., port 80) and would
     * close the WS frame even on a perfectly valid setup, producing false
     * negatives. UUID / backend-routing misconfigurations surface as "0 bytes
     * transferred" thanks to honest byte counting in [handleVlessTcp] /
     * [handleVlessWs], which is good enough — and has no false positives.
     *
     * Must be called after [start] has returned success.
     */
    fun probe(timeoutMs: Int = 10_000): Result<Unit> {
        if (!isRunning()) return Result.failure(IllegalStateException("VlessBridge not running"))
        var tunnel: Socket? = null
        var retainedAsWarm = false
        return try {
            tunnel = connectUpstreamTunnel(timeoutMs, timeoutMs)
            val tIn = BufferedInputStream(tunnel.getInputStream())
            val tOut = tunnel.getOutputStream()

            // For WS transport, verify the upgrade completes — that confirms
            // the WS path is correct and the Worker is accepting clients.
            // For TCP transport there's nothing else to probe structurally
            // (VLESS auth happens per-flow and we deliberately skip it here).
            if (transport == "ws") {
                val wsKey = generateWsKey()
                tOut.write(buildWsUpgradeRequest(wsKey).toByteArray(Charsets.US_ASCII))
                tOut.flush()
                val statusLine = readLine(tIn) ?: throw Exception("No WS response (wrong CDN/domain?)")
                if ("101" !in statusLine) throw Exception("WS upgrade failed: $statusLine (check wsPath)")
                // Drain response headers so the server finishes its write.
                while (true) { val line = readLine(tIn) ?: break; if (line.isEmpty()) break }

                if (BuildConfig.PERSONAL_BUILD && echMode == EchMode.REQUIRED) {
                    tunnel.soTimeout = 0
                    val warm = WarmWsTunnel(tunnel, tIn, tOut, SystemClock.elapsedRealtimeNanos())
                    warmWsTunnel.getAndSet(warm)?.let { previous ->
                        try { previous.socket.close() } catch (_: Exception) {}
                    }
                    retainedAsWarm = true
                    Log.operational("WARM_WS_STORED")
                }
            }

            Log.i(TAG, "VLESS probe succeeded (structural)")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.w(TAG, "VLESS probe failed: ${e.javaClass.simpleName} ${e.message}")
            Result.failure(e)
        } finally {
            if (!retainedAsWarm) try { tunnel?.close() } catch (_: Exception) {}
        }
    }


    /**
     * Authenticated backend probe for Personal EA.
     *
     * The structural probe above intentionally stops after WS 101 so its socket
     * can be retained as the first-flow warm tunnel. This second short-lived
     * connection verifies the VLESS UUID/backend path itself by asking Xray to
     * open a TCP stream to the server-local authenticated monitor endpoint.
     */
    fun probeAuthenticated(timeoutMs: Int = 10_000): Result<Unit> {
        if (!isRunning()) return Result.failure(IllegalStateException("VlessBridge not running"))
        var tunnel: Socket? = null
        return try {
            tunnel = connectUpstreamTunnel(timeoutMs, timeoutMs)
            tunnel.soTimeout = timeoutMs
            val input = BufferedInputStream(tunnel.getInputStream())
            val output = tunnel.getOutputStream()

            if (transport == "ws") {
                val wsKey = generateWsKey()
                output.write(buildWsUpgradeRequest(wsKey).toByteArray(Charsets.US_ASCII))
                output.flush()
                val statusLine = readLine(input)
                    ?: throw Exception("No WS response during authenticated probe")
                if ("101" !in statusLine) {
                    throw Exception("WS upgrade failed during authenticated probe: $statusLine")
                }
                while (true) {
                    val line = readLine(input) ?: break
                    if (line.isEmpty()) break
                }

                val request = buildVlessRequest(parseUUID(vlessUuid), "127.0.0.1", 8080)
                val probePayload = (
                    "GET / HTTP/1.1\r\n" +
                    "Host: localhost\r\n" +
                    "Connection: close\r\n\r\n"
                ).toByteArray(Charsets.US_ASCII)
                writeWsFrame(output, request + probePayload)

                val b0 = input.read()
                val b1 = input.read()
                if (b0 < 0 || b1 < 0) throw Exception("No VLESS auth response")
                val opcode = b0 and 0x0F
                if (opcode == 0x08) throw Exception("VLESS auth rejected (WS close)")

                val masked = (b1 and 0x80) != 0
                var payloadLen = (b1 and 0x7F).toLong()
                if (payloadLen == 126L) {
                    val h = input.read(); val l = input.read()
                    if (h < 0 || l < 0) throw Exception("Truncated VLESS auth frame")
                    payloadLen = ((h shl 8) or l).toLong()
                } else if (payloadLen == 127L) {
                    var len = 0L
                    repeat(8) {
                        val b = input.read()
                        if (b < 0) throw Exception("Truncated VLESS auth frame")
                        len = (len shl 8) or b.toLong()
                    }
                    payloadLen = len
                }
                if (payloadLen > 4096L) throw Exception("Unexpected VLESS auth frame size: $payloadLen")

                var maskKey: ByteArray? = null
                if (masked) {
                    maskKey = ByteArray(4)
                    readFully(input, maskKey)
                }
                val payload = ByteArray(payloadLen.toInt())
                if (payload.isNotEmpty()) {
                    readFully(input, payload)
                    if (maskKey != null) {
                        for (i in payload.indices) {
                            payload[i] = (payload[i].toInt() xor maskKey[i % 4].toInt()).toByte()
                        }
                    }
                }
                if (payload.size < 2) throw Exception("Invalid VLESS auth response")
                if (payload[0] != VLESS_VERSION) throw Exception("Unexpected VLESS response version")
                val addonsLen = payload[1].toInt() and 0xFF
                if (2 + addonsLen > payload.size) throw Exception("Truncated VLESS auth response")
            } else {
                val request = buildVlessRequest(parseUUID(vlessUuid), "127.0.0.1", 8080)
                val probePayload = (
                    "GET / HTTP/1.1\r\n" +
                    "Host: localhost\r\n" +
                    "Connection: close\r\n\r\n"
                ).toByteArray(Charsets.US_ASCII)
                output.write(request)
                output.write(probePayload)
                output.flush()
                val version = input.read()
                val addonsLen = input.read()
                if (version < 0 || addonsLen < 0) throw Exception("No VLESS auth response")
                if (version != VLESS_VERSION.toInt()) throw Exception("Unexpected VLESS response version")
                if (addonsLen > 0) {
                    val addons = ByteArray(addonsLen)
                    readFully(input, addons)
                }
            }

            Log.operational("VLESS_AUTH_PROBE_OK")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.operational("VLESS_AUTH_PROBE_FAILED")
            Log.w(TAG, "VLESS authenticated probe failed: ${e.javaClass.simpleName} ${e.message}")
            Result.failure(e)
        } finally {
            try { tunnel?.close() } catch (_: Exception) {}
        }
    }

    // ── SOCKS5 Handling ──────────────────────────────────────────────

    private fun handleSocks5Connection(client: Socket) {
        val flowId = nextFlowId.getAndIncrement()
        val acceptedNs = SystemClock.elapsedRealtimeNanos()
        Log.operational("SOCKS_ACCEPT", "flow" to flowId)
        try {
            Log.d(TAG, "SOCKS5 connection from ${client.remoteSocketAddress}")
            client.tcpNoDelay = true
            val input = BufferedInputStream(client.getInputStream())
            val output = client.getOutputStream()

            // SOCKS5 greeting: version(1) + nmethods(1) + methods(n)
            val ver = input.read()
            if (ver != 0x05) { client.close(); return }
            val nMethods = input.read()
            val methods = ByteArray(nMethods)
            readFully(input, methods)
            // Reply: no auth required
            output.write(byteArrayOf(0x05, 0x00))
            output.flush()

            // SOCKS5 request: ver(1) + cmd(1) + rsv(1) + atyp(1) + addr + port(2)
            val reqVer = input.read()
            val cmd = input.read()
            val rsv = input.read()
            val atyp = input.read()

            if (reqVer != 0x05 || cmd != 0x01) {
                // Only CONNECT is supported
                output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                output.flush()
                client.close()
                return
            }

            val destHost: String
            val destPort: Int

            when (atyp) {
                0x01 -> { // IPv4
                    val addr = ByteArray(4)
                    readFully(input, addr)
                    destHost = "${addr[0].toInt() and 0xFF}.${addr[1].toInt() and 0xFF}.${addr[2].toInt() and 0xFF}.${addr[3].toInt() and 0xFF}"
                }
                0x03 -> { // Domain
                    val len = input.read()
                    val domain = ByteArray(len)
                    readFully(input, domain)
                    destHost = String(domain, Charsets.US_ASCII)
                }
                0x04 -> { // IPv6
                    val addr = ByteArray(16)
                    readFully(input, addr)
                    val sb = StringBuilder()
                    for (i in 0 until 16 step 2) {
                        if (i > 0) sb.append(':')
                        sb.append(String.format("%02x%02x", addr[i], addr[i + 1]))
                    }
                    destHost = sb.toString()
                }
                else -> {
                    client.close(); return
                }
            }

            val portHi = input.read()
            val portLo = input.read()
            destPort = (portHi shl 8) or portLo

            Log.d(TAG, "SOCKS5 CONNECT $destHost:$destPort")

            // Reply success (we'll connect through VLESS)
            output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            output.flush()

            // Read first payload from client (e.g., TLS ClientHello) to bundle with VLESS header.
            // This avoids a deadlock where the remote server waits for data before responding.
            val firstPayload = ByteArray(BUFFER_SIZE)
            val firstPayloadLen = input.read(firstPayload)
            if (firstPayloadLen <= 0) {
                Log.operational("FLOW_NO_PAYLOAD", "flow" to flowId, "ms" to elapsedMs(acceptedNs))
                return
            }
            val initialData = firstPayload.copyOf(firstPayloadLen)
            // Account at the client/VPN boundary exactly once. A stale warm socket may
            // replay this buffered payload on a fresh upstream, but that transport retry
            // is not new user traffic and must not inflate the UI counter.
            tunnelTxBytes.addAndGet(initialData.size.toLong())
            val firstPayloadNs = SystemClock.elapsedRealtimeNanos()
            Log.operational(
                "FIRST_PAYLOAD_RECEIVED",
                "flow" to flowId,
                "accept_to_payload_ms" to elapsedMs(acceptedNs),
                "bytes" to initialData.size.toLong(),
            )
            logd("First payload from client: ${initialData.size} bytes for $destHost:$destPort")

            // Establish VLESS tunnel to destination
            handleVlessConnect(client, input, destHost, destPort, initialData, flowId, acceptedNs, firstPayloadNs)

        } catch (e: Exception) {
            Log.operational("FLOW_FAILED_SOCKS", "flow" to flowId, "ms" to elapsedMs(acceptedNs))
            Log.e(TAG, "SOCKS5 error: ${e.message}")
        } finally {
            Log.operational(
                "FLOW_CLOSED",
                "flow" to flowId,
                "ms" to elapsedMs(acceptedNs),
                "tx_total" to tunnelTxBytes.get(),
                "rx_total" to tunnelRxBytes.get(),
            )
            try { client.close() } catch (_: Exception) {}
            connectionThreads.remove(Thread.currentThread())
        }
    }

    // ── VLESS Connection ─────────────────────────────────────────────

    private fun handleVlessConnect(
        client: Socket,
        clientInput: InputStream,
        destHost: String,
        destPort: Int,
        initialData: ByteArray = ByteArray(0),
        flowId: Long,
        acceptedNs: Long,
        firstPayloadNs: Long,
    ) {
        var tunnelSocket: Socket? = null
        try {
            if (transport == "ws") {
                val warm = warmWsTunnel.getAndSet(null)
                scheduleWarmWsRefill()
                if (warm != null) {
                    tunnelSocket = warm.socket
                    Log.operational(
                        "WARM_WS_REUSED",
                        "flow" to flowId,
                        "age_ms" to elapsedMs(warm.createdAtNs),
                        "from_accept_ms" to elapsedMs(acceptedNs),
                    )
                    try {
                        handleVlessWs(
                            client, clientInput, warm.socket, warm.input, warm.output, destHost, destPort,
                            initialData, flowId, acceptedNs, wsAlreadyUpgraded = true,
                        )
                        return
                    } catch (_: Exception) {
                        Log.operational("WARM_WS_REUSE_FAILED", "flow" to flowId, "ms" to elapsedMs(acceptedNs))
                        try { warm.socket.close() } catch (_: Exception) {}
                        tunnelSocket = null
                    }
                }
            }

            val upstreamStartNs = SystemClock.elapsedRealtimeNanos()
            tunnelSocket = connectUpstreamTunnel(
                handshakeTimeoutMs = 15_000,
                finalReadTimeoutMs = VLESS_SESSION_ESTABLISHMENT_TIMEOUT_MS,
                telemetryFlowId = flowId,
            )
            Log.operational(
                "TLS_ECH_COMPLETE",
                "flow" to flowId,
                "upstream_ms" to elapsedMs(upstreamStartNs),
                "payload_to_tls_ms" to elapsedMs(firstPayloadNs),
            )
            val tunnelIn = BufferedInputStream(tunnelSocket.getInputStream())
            val tunnelOut = tunnelSocket.getOutputStream()
            if (tunnelSocket is SSLSocket) {
                Log.d(TAG, "TLS handshake complete (${tunnelSocket.session.protocol})")
            }

            if (transport == "tcp") {
                handleVlessTcp(client, tunnelIn, tunnelOut, destHost, destPort, initialData)
            } else {
                handleVlessWs(client, clientInput, tunnelSocket, tunnelIn, tunnelOut, destHost, destPort, initialData, flowId, acceptedNs)
            }
        } catch (e: Exception) {
            Log.operational("FLOW_FAILED_UPSTREAM_OR_SESSION", "flow" to flowId, "ms" to elapsedMs(acceptedNs))
            Log.e(TAG, "VLESS connect error for $destHost:$destPort: ${e.message}")
        } finally {
            try { tunnelSocket?.close() } catch (_: Exception) {}
        }
    }

    /**
     * TCP transport: VLESS header + raw bidirectional relay (no WebSocket framing).
     *
     * NOT EXPOSED IN THE UI — WebSocket is the only user-selectable transport.
     * The profile editor has no transport selector, and the URI importer rejects
     * `type=tcp` with a warning. Reason: SlipNet's VLESS is positioned as a
     * CDN-fronted tunnel, and raw TCP defeats that (no CDN to hide behind, no
     * TLS ClientHello for SNI fragmentation to fragment). Re-expose only if a
     * concrete non-CDN use case shows up.
     */
    private fun handleVlessTcp(client: Socket, tunnelIn: InputStream, tunnelOut: OutputStream, destHost: String, destPort: Int, initialData: ByteArray = ByteArray(0)) {

        // Send VLESS header + initial payload in one write
        val uuid = parseUUID(vlessUuid)
        val vlessHeader = buildVlessRequest(uuid, destHost, destPort)
        tunnelOut.write(vlessHeader)
        if (initialData.isNotEmpty()) {
            tunnelOut.write(initialData)
        }
        tunnelOut.flush()

        // Read VLESS response: version(1) + addons_len(1) + [addons] + optional payload
        val respVersion = tunnelIn.read()
        if (respVersion < 0) throw Exception("No VLESS response")
        val respAddonsLen = tunnelIn.read()
        if (respAddonsLen < 0) throw Exception("Truncated VLESS response")
        if (respAddonsLen > 0) {
            val addons = ByteArray(respAddonsLen)
            readFully(tunnelIn, addons)
        }

        logd("VLESS/TCP session established for $destHost:$destPort")

        // Raw bidirectional relay (no WS framing)
        relayRaw(client, tunnelIn, tunnelOut)
    }

    /**
     * WebSocket transport: WS upgrade with VLESS early data + WS-framed relay.
     *
     * WebSocket transport: WS upgrade + VLESS header as WS frame.
     */
    private fun handleVlessWs(
        client: Socket,
        clientInput: InputStream,
        tunnelSocket: Socket,
        tunnelIn: InputStream,
        tunnelOut: OutputStream,
        destHost: String,
        destPort: Int,
        initialData: ByteArray = ByteArray(0),
        flowId: Long,
        acceptedNs: Long,
        wsAlreadyUpgraded: Boolean = false,
    ) {
        if (!wsAlreadyUpgraded) {
            val wsKey = generateWsKey()
            val upgrade = buildWsUpgradeRequest(wsKey)
            tunnelOut.write(upgrade.toByteArray(Charsets.US_ASCII))
            tunnelOut.flush()

            // Read and log the full 101 response
            val statusLine = readLine(tunnelIn)
            if (statusLine == null || "101" !in statusLine) {
                Log.operational("FLOW_FAILED_WS_UPGRADE", "flow" to flowId, "ms" to elapsedMs(acceptedNs))
                Log.w(TAG, "WebSocket upgrade failed: $statusLine")
                tunnelSocket.close()
                return
            }
            val responseHeaders = mutableListOf(statusLine)
            while (true) {
                val line = readLine(tunnelIn) ?: break
                if (line.isEmpty()) break
                responseHeaders.add(line)
            }
            Log.operational("WS_101_COMPLETE", "flow" to flowId, "from_accept_ms" to elapsedMs(acceptedNs))
            Log.d(TAG, "WS upgrade for $destHost:$destPort — ${responseHeaders.joinToString(" | ")}")
        }

        // Warm sockets must remain replay-safe: if one is stale, do not consume any
        // additional client bytes before falling back to a fresh connection. Fresh
        // sockets can safely pump upstream while waiting for the VLESS response; this
        // avoids a pre-session deadlock when the destination needs more than the first
        // buffered chunk before it produces a response.
        tunnelSocket.soTimeout = if (wsAlreadyUpgraded) {
            WARM_VLESS_RESPONSE_TIMEOUT_MS
        } else {
            VLESS_SESSION_ESTABLISHMENT_TIMEOUT_MS
        }

        // Send VLESS header + initial payload bundled in a single WS frame.
        val uuid = parseUUID(vlessUuid)
        val vlessHeader = buildVlessRequest(uuid, destHost, destPort)
        val bundled = if (initialData.isNotEmpty()) {
            vlessHeader + initialData
        } else {
            vlessHeader
        }
        Log.d(TAG, "VLESS request (${vlessHeader.size}b header + ${initialData.size}b payload) for $destHost:$destPort")
        writeWsFrame(tunnelOut, bundled)

        val preResponseUpload = if (!wsAlreadyUpgraded) {
            startWsUploadPump(clientInput, tunnelOut).also {
                Log.operational("PRE_RESPONSE_UPLOAD_STARTED", "flow" to flowId)
            }
        } else null

        // Read server response. Some destinations do not produce downstream data until
        // a large upload finishes, and Xray can defer the VLESS response header with it.
        // Fresh sockets therefore extend the wait while upload bytes are still making
        // progress. A true no-progress stall still fails after the bounded timeout.
        var b0: Int
        var b1: Int
        while (true) {
            try {
                b0 = tunnelIn.read()
                if (b0 < 0) {
                    Log.operational("FLOW_FAILED_VLESS_RESPONSE", "flow" to flowId, "ms" to elapsedMs(acceptedNs))
                    throw Exception("No VLESS response (EOF)")
                }
                b1 = tunnelIn.read()
                if (b1 < 0) {
                    Log.operational("FLOW_FAILED_VLESS_RESPONSE", "flow" to flowId, "ms" to elapsedMs(acceptedNs))
                    throw Exception("No VLESS response (EOF after b0=${String.format("%02x", b0)})")
                }
                break
            } catch (timeout: SocketTimeoutException) {
                val canExtendFreshWait = if (!wsAlreadyUpgraded && preResponseUpload != null) {
                    val completed = preResponseUpload.completedNs.get()
                    val anchor = if (completed > 0L) {
                        maxOf(preResponseUpload.lastProgressNs.get(), completed)
                    } else {
                        preResponseUpload.lastProgressNs.get()
                    }
                    elapsedMs(anchor) < VLESS_SESSION_ESTABLISHMENT_TIMEOUT_MS
                } else false

                if (canExtendFreshWait) {
                    Log.operational(
                        "FLOW_VLESS_RESPONSE_WAIT_EXTENDED",
                        "flow" to flowId,
                        "ms" to elapsedMs(acceptedNs),
                    )
                    continue
                }

                Log.operational(
                    "FLOW_VLESS_RESPONSE_TIMEOUT",
                    "flow" to flowId,
                    "ms" to elapsedMs(acceptedNs),
                    "warm" to if (wsAlreadyUpgraded) 1L else 0L,
                )
                preResponseUpload?.let { stopWsUploadPump(it) }
                throw timeout
            } catch (error: Throwable) {
                preResponseUpload?.let { stopWsUploadPump(it) }
                throw error
            }
        }

        val opcode = b0 and 0x0F
        val fin = (b0 and 0x80) != 0
        val masked = (b1 and 0x80) != 0
        var payloadLen = (b1 and 0x7F).toLong()
        Log.d(TAG, "WS frame: fin=$fin opcode=$opcode masked=$masked len=$payloadLen for $destHost:$destPort")

        if (opcode == 0x08) throw Exception("Server sent WS close frame")

        if (payloadLen == 126L) {
            val h = tunnelIn.read(); val l = tunnelIn.read()
            if (h < 0 || l < 0) throw Exception("Truncated extended length")
            payloadLen = ((h shl 8) or l).toLong()
        } else if (payloadLen == 127L) {
            var len = 0L
            for (i in 0 until 8) { val b = tunnelIn.read(); if (b < 0) throw Exception("Truncated 64-bit length"); len = (len shl 8) or b.toLong() }
            payloadLen = len
        }

        var maskKey: ByteArray? = null
        if (masked) { maskKey = ByteArray(4); readFully(tunnelIn, maskKey) }

        if (payloadLen > 16 * 1024 * 1024) throw Exception("Frame too large: $payloadLen")

        val payload = ByteArray(payloadLen.toInt())
        if (payloadLen > 0) {
            readFully(tunnelIn, payload)
            if (maskKey != null) { for (i in payload.indices) { payload[i] = (payload[i].toInt() xor maskKey[i % 4].toInt()).toByte() } }
        }

        Log.d(TAG, "VLESS response (${payload.size}b): ${payload.take(16).joinToString(" ") { String.format("%02x", it) }} for $destHost:$destPort")

        if (payload.size < 2) throw Exception("Invalid VLESS response (${payload.size} bytes)")
        // Establishment is complete. Do not impose a read deadline on the live tunnel.
        tunnelSocket.soTimeout = 0
        val respAddonsLen = payload[1].toInt() and 0xFF
        val responsePayloadOffset = 2 + respAddonsLen
        var firstUsefulByteDelivered = false
        if (responsePayloadOffset < payload.size) {
            val initialData = payload.copyOfRange(responsePayloadOffset, payload.size)
            client.getOutputStream().write(initialData)
            client.getOutputStream().flush()
            tunnelRxBytes.addAndGet(initialData.size.toLong())
            firstUsefulByteDelivered = true
            Log.operational(
                "FIRST_USEFUL_BYTE",
                "flow" to flowId,
                "from_accept_ms" to elapsedMs(acceptedNs),
                "bytes" to initialData.size.toLong(),
            )
        }

        Log.operational("VLESS_SESSION_ESTABLISHED", "flow" to flowId, "from_accept_ms" to elapsedMs(acceptedNs))
        Log.i(TAG, "VLESS/WS session established for $destHost:$destPort")

        // Bidirectional relay with WS framing
        relayVless(client, clientInput, tunnelIn, tunnelOut, flowId, acceptedNs, firstUsefulByteDelivered, preResponseUpload)
    }

    /**
     * Raw bidirectional relay for TCP transport (no WebSocket framing).
     */
    private fun relayRaw(client: Socket, tlsIn: InputStream, tlsOut: OutputStream) {
        val executor = Executors.newFixedThreadPool(2)
        val clientIn = client.getInputStream()
        val clientOut = client.getOutputStream()

        // Client -> VLESS server (raw)
        val f1 = executor.submit {
            try {
                val buf = ByteArray(BUFFER_SIZE)
                while (!Thread.currentThread().isInterrupted) {
                    val n = clientIn.read(buf)
                    if (n <= 0) break
                    // Count what the client handed to the VPN, independent of whether
                    // the current upstream write later succeeds or is retried.
                    tunnelTxBytes.addAndGet(n.toLong())
                    tlsOut.write(buf, 0, n)
                    tlsOut.flush()
                }
            } catch (_: Exception) {}
        }

        // VLESS server -> Client (raw)
        val f2 = executor.submit {
            try {
                val buf = ByteArray(BUFFER_SIZE)
                while (!Thread.currentThread().isInterrupted) {
                    val n = tlsIn.read(buf)
                    if (n <= 0) break
                    clientOut.write(buf, 0, n)
                    clientOut.flush()
                    tunnelRxBytes.addAndGet(n.toLong())
                }
            } catch (_: Exception) {}
        }

        try { f1.get() } catch (_: Exception) {}
        try { f2.get() } catch (_: Exception) {}
        executor.shutdownNow()
    }

    /**
     * Build VLESS request header.
     * Format: version(1) + UUID(16) + addons_len(1) + command(1) + port(2) + addr_type(1) + addr
     */
    private fun buildVlessRequest(uuid: ByteArray, host: String, port: Int): ByteArray {
        val buf = ByteArrayOutputStream()
        buf.write(VLESS_VERSION.toInt())
        buf.write(uuid)
        buf.write(0) // addons length = 0

        buf.write(VLESS_CMD_TCP.toInt())
        buf.write(port shr 8 and 0xFF)
        buf.write(port and 0xFF)

        // Check if host is an IP address
        val ipv4Regex = Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
        if (ipv4Regex.matches(host)) {
            buf.write(VLESS_ADDR_IPV4.toInt())
            host.split('.').forEach { buf.write(it.toInt()) }
        } else if (host.contains(':')) {
            // IPv6
            buf.write(VLESS_ADDR_IPV6.toInt())
            val parts = expandIPv6(host)
            for (part in parts) {
                buf.write(part shr 8 and 0xFF)
                buf.write(part and 0xFF)
            }
        } else {
            // Domain
            buf.write(VLESS_ADDR_DOMAIN.toInt())
            val domainBytes = host.toByteArray(Charsets.US_ASCII)
            buf.write(domainBytes.size)
            buf.write(domainBytes)
        }

        return buf.toByteArray()
    }

    private data class WsUploadPump(
        val executor: ExecutorService,
        val future: Future<*>,
        val lastProgressNs: AtomicLong,
        val completedNs: AtomicLong,
    )

    private fun startWsUploadPump(clientInput: InputStream, wsOutput: OutputStream): WsUploadPump {
        val executor = Executors.newSingleThreadExecutor()
        val lastProgressNs = AtomicLong(SystemClock.elapsedRealtimeNanos())
        val completedNs = AtomicLong(0L)
        lateinit var pump: WsUploadPump
        val future = executor.submit {
            var readBytes = 0L
            var writtenBytes = 0L
            var frames = 0L
            try {
                val buf = ByteArray(BUFFER_SIZE)
                while (!Thread.currentThread().isInterrupted) {
                    val n = clientInput.read(buf)
                    if (n <= 0) break
                    readBytes += n.toLong()
                    // Count once at SOCKS ingress. If this upstream dies after the read,
                    // a transport replay/fallback must not count these same bytes twice.
                    tunnelTxBytes.addAndGet(n.toLong())
                    synchronized(wsOutput) {
                        writeWsFrame(wsOutput, buf, length = n)
                    }
                    writtenBytes += n.toLong()
                    frames++
                    lastProgressNs.set(SystemClock.elapsedRealtimeNanos())
                }
            } catch (error: Exception) {
                Log.operational(
                    "WS_UPLOAD_PUMP_FAILED",
                    "read" to readBytes,
                    "written" to writtenBytes,
                    "frames" to frames,
                )
                Log.w(TAG, "WS upload pump failed: ${error.javaClass.simpleName}")
            } finally {
                completedNs.compareAndSet(0L, SystemClock.elapsedRealtimeNanos())
            }
        }
        pump = WsUploadPump(executor, future, lastProgressNs, completedNs)
        return pump
    }

    private fun stopWsUploadPump(pump: WsUploadPump) {
        pump.future.cancel(true)
        pump.executor.shutdownNow()
    }

    /**
     * Relay data between client and WebSocket-framed VLESS tunnel.
     * Client side is raw TCP; tunnel side uses WebSocket binary frames.
     */
    private fun relayVless(
        client: Socket,
        clientInput: InputStream,
        wsInput: InputStream,
        wsOutput: OutputStream,
        flowId: Long,
        acceptedNs: Long,
        firstUsefulByteAlreadyDelivered: Boolean,
        preResponseUpload: WsUploadPump?,
    ) {
        val clientOut = client.getOutputStream()
        val firstUsefulByteDelivered = AtomicBoolean(firstUsefulByteAlreadyDelivered)
        val upload = preResponseUpload ?: startWsUploadPump(clientInput, wsOutput)
        val executor = Executors.newFixedThreadPool(if (wsPaddingEnabled) 2 else 1)
        val f1 = upload.future

        // VLESS -> Client (unwrap WS frames)
        val f2 = executor.submit {
            try {
                while (!Thread.currentThread().isInterrupted) {
                    val frame = readWsFrame(wsInput) ?: break
                    if (frame.isEmpty()) continue
                    clientOut.write(frame)
                    clientOut.flush()
                    tunnelRxBytes.addAndGet(frame.size.toLong())
                    if (firstUsefulByteDelivered.compareAndSet(false, true)) {
                        Log.operational(
                            "FIRST_USEFUL_BYTE",
                            "flow" to flowId,
                            "from_accept_ms" to elapsedMs(acceptedNs),
                            "bytes" to frame.size.toLong(),
                        )
                    }
                }
            } catch (_: Exception) {}
        }

        // Cover traffic: send random-size WS ping frames at random intervals
        val coverPingCount = AtomicLong(0)
        val f3 = if (wsPaddingEnabled) executor.submit {
            Log.operational("COVER_TRAFFIC_STARTED", "flow" to flowId)
            try {
                while (!Thread.currentThread().isInterrupted) {
                    val delay = 500 + random.nextInt(2000) // 0.5-2.5s between pings
                    Thread.sleep(delay.toLong())
                    val pingSize = 4 + random.nextInt(120) // 4-124 bytes
                    val pingPayload = ByteArray(pingSize)
                    random.nextBytes(pingPayload)
                    synchronized(wsOutput) {
                        writeWsFrame(wsOutput, pingPayload, opcode = 0x09)
                    }
                    coverPingCount.incrementAndGet()
                }
            } catch (_: Exception) {}
        } else null

        try { f1.get() } catch (_: Exception) {}
        try { f2.get() } catch (_: Exception) {}
        f3?.cancel(true)
        try { f3?.get() } catch (_: Exception) {}
        stopWsUploadPump(upload)
        executor.shutdownNow()
        if (wsPaddingEnabled) {
            Log.operational(
                "COVER_TRAFFIC_STOPPED",
                "flow" to flowId,
                "pings" to coverPingCount.get(),
            )
        }
    }

    // ── WebSocket Framing (RFC 6455) ─────────────────────────────────

    /**
     * Write a WebSocket frame with masking (client must mask).
     * Default opcode 0x02 = binary, 0x09 = ping.
     */
    private fun writeWsFrame(
        out: OutputStream,
        payload: ByteArray,
        length: Int = payload.size,
        opcode: Int = 0x02,
    ) {
        require(length in 0..payload.size)
        val len = length

        // Build the RFC 6455 client header without ByteArrayOutputStream allocation.
        val header = ByteArray(14)
        var h = 0
        header[h++] = (0x80 or opcode).toByte()
        when {
            len <= 125 -> header[h++] = (0x80 or len).toByte()
            len <= 65535 -> {
                header[h++] = (0x80 or 126).toByte()
                header[h++] = (len ushr 8).toByte()
                header[h++] = len.toByte()
            }
            else -> {
                header[h++] = (0x80 or 127).toByte()
                val longLen = len.toLong()
                for (i in 7 downTo 0) header[h++] = (longLen ushr (i * 8)).toByte()
            }
        }

        // One shared SecureRandom supplies unpredictable masks; do not instantiate a
        // provider/PRNG for every frame. The output stream is already serialized per flow.
        val mask = random.nextInt()
        val m0 = mask ushr 24 and 0xff
        val m1 = mask ushr 16 and 0xff
        val m2 = mask ushr 8 and 0xff
        val m3 = mask and 0xff
        header[h++] = m0.toByte()
        header[h++] = m1.toByte()
        header[h++] = m2.toByte()
        header[h++] = m3.toByte()

        var masked = wsMaskScratch.get() ?: ByteArray(BUFFER_SIZE).also(wsMaskScratch::set)
        if (masked.size < len) {
            masked = ByteArray(len)
            wsMaskScratch.set(masked)
        }
        for (i in 0 until len) {
            val key = when (i and 3) { 0 -> m0; 1 -> m1; 2 -> m2; else -> m3 }
            masked[i] = (payload[i].toInt() xor key).toByte()
        }

        out.write(header, 0, h)
        out.write(masked, 0, len)
        out.flush()
    }

    /**
     * Read a WebSocket frame. Returns payload bytes, or null on EOF/close.
     */
    private fun readWsFrame(input: InputStream): ByteArray? {
        val b0 = input.read()
        if (b0 < 0) return null
        val b1 = input.read()
        if (b1 < 0) return null

        val opcode = b0 and 0x0F
        val masked = (b1 and 0x80) != 0
        var payloadLen = (b1 and 0x7F).toLong()

        if (payloadLen == 126L) {
            val h = input.read()
            val l = input.read()
            if (h < 0 || l < 0) return null
            payloadLen = ((h shl 8) or l).toLong()
        } else if (payloadLen == 127L) {
            var len = 0L
            for (i in 0 until 8) {
                val b = input.read()
                if (b < 0) return null
                len = (len shl 8) or b.toLong()
            }
            payloadLen = len
        }

        var maskKey: ByteArray? = null
        if (masked) {
            maskKey = ByteArray(4)
            readFully(input, maskKey)
        }

        if (payloadLen > 16 * 1024 * 1024) return null // 16MB sanity limit

        val payload = ByteArray(payloadLen.toInt())
        if (payloadLen > 0) {
            readFully(input, payload)
            if (maskKey != null) {
                for (i in payload.indices) {
                    payload[i] = (payload[i].toInt() xor maskKey[i % 4].toInt()).toByte()
                }
            }
        }

        return when (opcode) {
            0x01, 0x02, 0x00 -> payload // text, binary, continuation
            0x08 -> null // close
            0x09 -> { // ping -> pong
                // Server shouldn't mask, we just read it. Don't reply with pong for simplicity.
                ByteArray(0)
            }
            0x0A -> ByteArray(0) // pong (ignore)
            else -> payload
        }
    }

    // ── DPI Evasion ──────────────────────────────────────────────────

    /** Browser User-Agent strings for header obfuscation. */
    private val userAgents = listOf(
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.101 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36"
    )

    /**
     * Build the WebSocket upgrade request.
     *
     * When header obfuscation is enabled, adds browser-like headers (User-Agent, Accept, etc.)
     * and randomizes header order to defeat DPI that fingerprints by header structure.
     */
    private fun buildWsUpgradeRequest(wsKey: String): String {
        if (!wsHeaderObfuscation) {
            return "GET $wsPath HTTP/1.1\r\n" +
                    "Host: $serverDomain\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Sec-WebSocket-Key: $wsKey\r\n" +
                    "Sec-WebSocket-Version: 13\r\n" +
                    "\r\n"
        }

        val headers = mutableListOf(
            "Host: $serverDomain",
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Key: $wsKey",
            "Sec-WebSocket-Version: 13",
            "User-Agent: ${userAgents[random.nextInt(userAgents.size)]}",
            "Accept-Language: en-US,en;q=0.9",
            "Accept-Encoding: gzip, deflate, br",
            "Cache-Control: no-cache",
            "Pragma: no-cache"
        )
        headers.shuffle(random)

        return "GET $wsPath HTTP/1.1\r\n" +
                headers.joinToString("\r\n") + "\r\n\r\n"
    }

    // ── Utility ──────────────────────────────────────────────────────

    /**
     * SNI for the CDN TLS handshake: the explicit [vlessSni], or the WS Host
     * ([serverDomain]) when none is set. Matches V2Ray's single-serverName model.
     */
    private fun resolveSni(): String = vlessSni.ifBlank { serverDomain }

    private fun parseUUID(uuid: String): ByteArray {
        val hex = uuid.replace("-", "")
        require(hex.length == 32) { "Invalid UUID: $uuid" }
        val bytes = ByteArray(16)
        for (i in 0 until 16) {
            bytes[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return bytes
    }

    private fun generateWsKey(): String {
        val bytes = ByteArray(16)
        SecureRandom().nextBytes(bytes)
        return android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
    }

    private fun readFully(input: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n <= 0) throw java.io.EOFException("Unexpected EOF")
            off += n
        }
    }

    private fun readLine(input: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            if (b == '\n'.code) {
                val s = sb.toString()
                return if (s.endsWith('\r')) s.dropLast(1) else s
            }
            sb.append(b.toChar())
        }
    }

    private fun expandIPv6(addr: String): List<Int> {
        // Simple IPv6 expansion — enough for address encoding
        val parts = addr.split(':').map { if (it.isEmpty()) 0 else it.toInt(16) }
        if (parts.size == 8) return parts
        // Handle :: expansion
        val result = mutableListOf<Int>()
        val sections = addr.split("::")
        val left = if (sections[0].isEmpty()) emptyList() else sections[0].split(':').map { it.toInt(16) }
        val right = if (sections.size > 1 && sections[1].isNotEmpty()) sections[1].split(':').map { it.toInt(16) } else emptyList()
        result.addAll(left)
        repeat(8 - left.size - right.size) { result.add(0) }
        result.addAll(right)
        return result
    }

    private fun bindServerSocket(host: String, port: Int): ServerSocket {
        for (attempt in 0 until BIND_MAX_RETRIES) {
            try {
                val ss = ServerSocket()
                ss.reuseAddress = true
                ss.bind(InetSocketAddress(host, port))
                return ss
            } catch (e: Exception) {
                if (attempt < BIND_MAX_RETRIES - 1) {
                    Thread.sleep(BIND_RETRY_DELAY_MS)
                } else throw e
            }
        }
        throw IllegalStateException("Failed to bind after $BIND_MAX_RETRIES attempts")
    }
}
