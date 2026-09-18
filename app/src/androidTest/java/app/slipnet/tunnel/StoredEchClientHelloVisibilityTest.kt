package app.slipnet.tunnel

import android.content.Context
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import app.slipnet.testsupport.DeviceTestEntryPoint
import dagger.hilt.EntryPoints
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class StoredEchClientHelloVisibilityTest {
    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val entryPoint: DeviceTestEntryPoint get() =
        EntryPoints.get(context.applicationContext, DeviceTestEntryPoint::class.java)

    @Test
    fun currentStoredSeedClientHelloHidesProtectedName() = runBlocking {
        val profile = entryPoint.profileRepository().getActiveProfile().first()
        assertNotNull("active profile required", profile)
        val p = profile!!
        val config = EchConfigResolver.decodeStoredSeed(p.vlessEchConfigSeed)
        assertNotNull("stored ECH seed required", config)
        val serverName = p.vlessSni.ifBlank { p.domain }
        assertTrue("protected server name required", serverName.isNotBlank())
        val relay = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        relay.soTimeout = 20_000
        val captures = java.util.Collections.synchronizedList(mutableListOf<ByteArrayOutputStream>())
        val relayDone = CountDownLatch(1)
        val relayThread = Thread {
            try {
                repeat(2) {
                    val client = try { relay.accept() } catch (_: java.net.SocketTimeoutException) { return@repeat }
                    val upstream = Socket().apply {
                        connect(InetSocketAddress(p.cdnIp, p.cdnPort), 10_000)
                        soTimeout = 15_000
                    }
                    val captured = ByteArrayOutputStream()
                    captures += captured
                    val upThread = Thread { relayClientToUpstream(client, upstream, captured) }
                    val downThread = Thread { relayStream(upstream, client) }
                    upThread.start(); downThread.start()
                    upThread.join(20_000); downThread.join(20_000)
                    try { client.close() } catch (_: Exception) {}
                    try { upstream.close() } catch (_: Exception) {}
                }
            } finally {
                relayDone.countDown()
            }
        }
        relayThread.start()
        val result = EchTlsCoordinator(EchBackends.current()).connect(
            EchMode.REQUIRED,
            EchConnectRequest(
                connectHost = "127.0.0.1",
                port = relay.localPort,
                serverName = serverName,
                configList = config,
            ),
        )
        assertTrue("ECH handshake through capture relay failed: $result", result is EchConnectResult.Connected)
        (result as EchConnectResult.Connected).socket.close()
        relay.close()
        relayDone.await(5, TimeUnit.SECONDS)

        val hellos = captures.mapNotNull { extractClientHello(it.toByteArray()) }
        assertTrue("ClientHello not captured", hellos.isNotEmpty())
        hellos.forEachIndexed { index, hello ->
            val echExtension = hasExtension(hello, 0xfe0d)
            val protectedVisible = containsAsciiIgnoreCase(hello, serverName)
            Log.i(TAG, "clientHelloIndex=$index;bytes=${hello.size};echExtension=$echExtension;protectedNameVisible=$protectedVisible")
            assertTrue("ECH extension 0xfe0d missing from visible ClientHello #$index", echExtension)
            assertFalse("protected inner hostname leaked in visible ClientHello #$index", protectedVisible)
        }
    }

    private fun relayClientToUpstream(client: Socket, upstream: Socket, captured: ByteArrayOutputStream) {
        val input = client.getInputStream(); val output = upstream.getOutputStream(); val buf = ByteArray(8192)
        try { while (true) { val n = input.read(buf); if (n <= 0) break; synchronized(captured) { if (captured.size() < 65536) captured.write(buf, 0, minOf(n, 65536 - captured.size())) }; output.write(buf, 0, n); output.flush() } } catch (_: Exception) {}
    }
    private fun relayStream(from: Socket, to: Socket) {
        val input = from.getInputStream(); val output = to.getOutputStream(); val buf = ByteArray(8192)
        try { while (true) { val n = input.read(buf); if (n <= 0) break; output.write(buf, 0, n); output.flush() } } catch (_: Exception) {}
    }

    private fun extractClientHello(records: ByteArray): ByteArray? {
        val handshake = ByteArrayOutputStream(); var p = 0
        while (p + 5 <= records.size) {
            val type = records[p].toInt() and 0xff
            val len = ((records[p + 3].toInt() and 0xff) shl 8) or (records[p + 4].toInt() and 0xff)
            if (p + 5 + len > records.size) break
            if (type == 22) handshake.write(records, p + 5, len)
            p += 5 + len
            val h = handshake.toByteArray()
            if (h.size >= 4 && (h[0].toInt() and 0xff) == 1) {
                val need = 4 + ((h[1].toInt() and 0xff) shl 16) + ((h[2].toInt() and 0xff) shl 8) + (h[3].toInt() and 0xff)
                if (h.size >= need) return h.copyOfRange(0, need)
            }
        }
        return null
    }

    private fun hasExtension(hello: ByteArray, target: Int): Boolean {
        if (hello.size < 42 || (hello[0].toInt() and 0xff) != 1) return false
        var p = 4 + 2 + 32
        val sid = hello[p].toInt() and 0xff; p += 1 + sid
        if (p + 2 > hello.size) return false
        val suites = u16(hello, p); p += 2 + suites
        if (p >= hello.size) return false
        val comp = hello[p].toInt() and 0xff; p += 1 + comp
        if (p + 2 > hello.size) return false
        val extTotal = u16(hello, p); p += 2
        val end = minOf(hello.size, p + extTotal)
        while (p + 4 <= end) { val type = u16(hello, p); val len = u16(hello, p + 2); if (type == target) return true; p += 4 + len }
        return false
    }
    private fun containsAsciiIgnoreCase(bytes: ByteArray, text: String): Boolean {
        val needle = text.lowercase().toByteArray(Charsets.US_ASCII)
        val hay = bytes.map { b ->
            val c = b.toInt() and 0xff
            if (c in 'A'.code..'Z'.code) (c + 32).toByte() else b
        }.toByteArray()
        if (needle.isEmpty() || needle.size > hay.size) return false
        for (i in 0..hay.size - needle.size) {
            var ok = true
            for (j in needle.indices) if (hay[i + j] != needle[j]) { ok = false; break }
            if (ok) return true
        }
        return false
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    companion object { private const val TAG = "SlipNetEAClientHello" }
}
