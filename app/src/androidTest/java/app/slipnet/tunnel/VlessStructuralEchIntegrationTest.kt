package app.slipnet.tunnel

import java.net.ServerSocket
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test

class VlessStructuralEchIntegrationTest {
    private val host = "websocket-template.signalnerve.workers.dev"

    @Test
    fun realVlessBridgeProbeSucceedsOverRequiredEch() = runBlocking {
        val config = EchConfigResolver.resolve(host, 10_000)
        assertTrue("ECHConfigList missing", config != null && config.isNotEmpty())

        val listenPort = ServerSocket(0).use { it.localPort }
        val start = VlessBridge.start(
            listenPort = listenPort,
            cdnIp = host,
            cdnPort = 443,
            serverDomain = host,
            vlessUuid = "00000000-0000-4000-8000-000000000000",
            security = "tls",
            transport = "ws",
            wsPath = "/ws",
            fragmentEnabled = false,
            vlessSni = host,
            echMode = EchMode.REQUIRED,
            echConfigList = config,
        )
        assertTrue("VlessBridge start failed", start.isSuccess)

        try {
            val probe = VlessBridge.probe(10_000)
            assertTrue("VlessBridge probe failed", probe.isSuccess)
        } finally {
            VlessBridge.stop()
        }
    }
}
