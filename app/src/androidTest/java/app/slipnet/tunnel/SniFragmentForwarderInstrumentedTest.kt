package app.slipnet.tunnel

import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class SniFragmentForwarderInstrumentedTest {
    @Test
    fun sniSplitAndMicroActuallyFragmentTcpWrites() {
        val args = InstrumentationRegistry.getArguments()
        val host = args.getString("fragment_host") ?: error("fragment_host missing")
        val ip = args.getString("fragment_ip") ?: error("fragment_ip missing")
        assertTrue("fragment target must be literal IP", DomainRouter.isIpAddress(ip))

        verifyStrategy(host, ip, "sni_split", minimumRecords = 2)
        verifyStrategy(host, ip, "micro", minimumRecords = 20)
    }

    @Test
    fun rawRelayBaselineTlsWorks() {
        val args = InstrumentationRegistry.getArguments()
        val host = args.getString("fragment_host") ?: error("fragment_host missing")
        val ip = args.getString("fragment_ip") ?: error("fragment_ip missing")
        val loopback = InetAddress.getByName("127.0.0.1")
        val relay = ServerSocket(0, 1, loopback).apply { soTimeout = 20_000 }
        val done = CountDownLatch(1)
        val t = Thread {
            var client: Socket? = null
            var upstream: Socket? = null
            try {
                client = relay.accept()
                upstream = Socket().apply { connect(InetSocketAddress(ip, 443), 10_000); soTimeout = 20_000 }
                val c = client!!; val u = upstream!!
                val a = Thread { copy(c, u, null) }; val b = Thread { copy(u, c, null) }
                a.start(); b.start(); a.join(25_000); b.join(25_000)
            } finally {
                try { client?.close() } catch (_: Exception) {}
                try { upstream?.close() } catch (_: Exception) {}
                done.countDown()
            }
        }
        t.start()
        val result = StandardTlsConnector().connect(EchConnectRequest("127.0.0.1", relay.localPort, host, null, 10_000, 20_000))
        assertTrue("raw relay TLS baseline failed: $result", result is EchConnectResult.Connected)
        (result as EchConnectResult.Connected).socket.close()
        relay.close(); done.await(5, TimeUnit.SECONDS)
    }

    private fun verifyStrategy(host: String, ip: String, strategy: String, minimumRecords: Int) {
        val result = runThroughFragmenter(host, ip, strategy)
        val writeCount = result.writeCount
        val reassembledHostVisible = containsAsciiIgnoreCase(result.capture, host)
        Log.i(TAG, "strategy=$strategy;fragmentWrites=$writeCount;sniBoundary=${result.sniBoundary};reassembledHostVisible=$reassembledHostVisible")
        assertTrue("$strategy did not emit enough TCP writes: $writeCount", writeCount >= minimumRecords)
        if (strategy == "sni_split") assertTrue("SNI split boundary was not inside hostname", result.sniBoundary)
        assertTrue("TCP reassembly should preserve the original TLS hostname bytes", reassembledHostVisible)
    }

    private data class FragmentRun(val capture: ByteArray, val writeCount: Int, val sniBoundary: Boolean)

    private fun runThroughFragmenter(host: String, ip: String, strategy: String): FragmentRun {
        val loopback = InetAddress.getByName("127.0.0.1")
        val relay = ServerSocket(0, 1, loopback).apply { soTimeout = 20_000 }
        val captured = ByteArrayOutputStream()
        val relayDone = CountDownLatch(1)
        val relayThread = Thread {
            var downstream: Socket? = null
            var upstream: Socket? = null
            try {
                downstream = relay.accept()
                upstream = Socket().apply {
                    connect(InetSocketAddress(ip, 443), 10_000)
                    soTimeout = 20_000
                }
                val d = downstream!!
                val u = upstream!!
                val up = Thread { copy(d, u, captured) }
                val down = Thread { copy(u, d, null) }
                up.start(); down.start()
                up.join(25_000); down.join(25_000)
            } finally {
                try { downstream?.close() } catch (_: Exception) {}
                try { upstream?.close() } catch (_: Exception) {}
                relayDone.countDown()
            }
        }
        relayThread.start()

        val forwardPort = ServerSocket(0, 1, loopback).use { it.localPort }
        val forwarder = SniFragmentForwarder("instrumented-$strategy").apply {
            connectIp = "127.0.0.1"
            connectPort = relay.localPort
            fragmentStrategy = strategy
            fragmentDelayMs = 10
            tcpMaxSeg = -1
        }
        val started = forwarder.start(forwardPort)
        assertTrue("fragmenter failed to start: $started", started.isSuccess)

        val result = StandardTlsConnector().connect(
            EchConnectRequest(
                connectHost = "127.0.0.1",
                port = forwardPort,
                serverName = host,
                configList = null,
                connectTimeoutMs = 10_000,
                readTimeoutMs = 20_000,
            )
        )
        assertTrue("TLS failed through $strategy fragmenter: $result", result is EchConnectResult.Connected)
        (result as EchConnectResult.Connected).socket.close()
        forwarder.stop()
        relay.close()
        relayDone.await(5, TimeUnit.SECONDS)
        return FragmentRun(captured.toByteArray(), forwarder.getLastFragmentWriteCount(), forwarder.wasLastSniSplitInsideHostname())
    }

    private fun copy(from: Socket, to: Socket, capture: ByteArrayOutputStream?) {
        val input = from.getInputStream()
        val output = to.getOutputStream()
        val buffer = ByteArray(8192)
        try {
            while (true) {
                val n = input.read(buffer)
                if (n <= 0) break
                if (capture != null && capture.size() < 131072) {
                    synchronized(capture) {
                        capture.write(buffer, 0, minOf(n, 131072 - capture.size()))
                    }
                }
                output.write(buffer, 0, n)
                output.flush()
            }
        } catch (_: Exception) {}
    }

    private fun countInitialHandshakeRecords(bytes: ByteArray): Int {
        var offset = 0
        var count = 0
        while (offset + 5 <= bytes.size) {
            val type = bytes[offset].toInt() and 0xff
            val length = ((bytes[offset + 3].toInt() and 0xff) shl 8) or (bytes[offset + 4].toInt() and 0xff)
            if (offset + 5 + length > bytes.size) break
            if (type != 22) break
            count++
            offset += 5 + length
        }
        return count
    }

    private fun containsAsciiIgnoreCase(bytes: ByteArray, text: String): Boolean {
        val needle = text.lowercase().toByteArray(Charsets.US_ASCII)
        if (needle.isEmpty() || needle.size > bytes.size) return false
        for (i in 0..bytes.size - needle.size) {
            var match = true
            for (j in needle.indices) {
                var c = bytes[i + j].toInt() and 0xff
                if (c in 'A'.code..'Z'.code) c += 32
                if (c.toByte() != needle[j]) { match = false; break }
            }
            if (match) return true
        }
        return false
    }

    private companion object {
        const val TAG = "SlipNetEAFragment"
    }
}
