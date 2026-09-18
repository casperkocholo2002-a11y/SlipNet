package app.slipnet.tunnel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class EchTlsCoordinatorTest {
    private val request = EchConnectRequest("203.0.113.10", 443, "example.com", byteArrayOf(1, 2, 3))

    @Test fun requiredFailureNeverFallsBack() {
        var fallbackCalls = 0
        val backend = QueueBackend(EchCapability.CONSCRYPT, mutableListOf(EchConnectResult.Failed(SSLException("fail"))))
        val result = EchTlsCoordinator(backend) { fallbackCalls++; EchConnectResult.Failed(SSLException("fallback")) }
            .connect(EchMode.REQUIRED, request)
        assertTrue(result is EchConnectResult.Failed)
        assertEquals(0, fallbackCalls)
    }

    @Test fun preferredFailureFallsBackOnce() {
        var fallbackCalls = 0
        val backend = QueueBackend(EchCapability.CONSCRYPT, mutableListOf(EchConnectResult.Failed(SSLException("fail"))))
        EchTlsCoordinator(backend) { fallbackCalls++; EchConnectResult.Failed(SSLException("fallback")) }
            .connect(EchMode.PREFERRED, request)
        assertEquals(1, fallbackCalls)
    }

    @Test fun platformRetryUsesFreshSecondAttemptOnlyOnce() {
        var fallbackCalls = 0
        val retry = byteArrayOf(9, 8, 7)
        val backend = QueueBackend(EchCapability.PLATFORM, mutableListOf(EchConnectResult.Retry(retry), EchConnectResult.Failed(SSLException("second fail"))))
        val result = EchTlsCoordinator(backend) { fallbackCalls++; EchConnectResult.Failed(SSLException("fallback")) }
            .connect(EchMode.REQUIRED, request)
        assertTrue(result is EchConnectResult.Failed)
        assertEquals(2, backend.requests.size)
        assertTrue(backend.requests[1].configList!!.contentEquals(retry))
        assertEquals(0, fallbackCalls)
    }

    @Test fun conscryptAuthenticatedRetryUsesFreshSecondAttemptOnlyOnce() {
        val retry = byteArrayOf(4, 5, 6)
        val backend = QueueBackend(
            EchCapability.CONSCRYPT,
            mutableListOf(EchConnectResult.Retry(retry), EchConnectResult.Failed(SSLException("second fail"))),
        )
        val result = EchTlsCoordinator(backend).connect(EchMode.REQUIRED, request)
        assertTrue(result is EchConnectResult.Failed)
        assertEquals(2, backend.requests.size)
        assertTrue(backend.requests[1].configList!!.contentEquals(retry))
    }

    @Test fun directEchSuccessDoesNotPublishSeedRenewal() {
        val accepted = mutableListOf<ByteArray>()
        val backend = QueueBackend(
            EchCapability.CONSCRYPT,
            mutableListOf(EchConnectResult.Connected(fakeSocket())),
        )
        val result = EchTlsCoordinator(
            backend = backend,
            onAuthenticatedRetryAccepted = { accepted += it },
        ).connect(EchMode.REQUIRED, request)
        assertTrue(result is EchConnectResult.Connected)
        assertTrue(accepted.isEmpty())
    }

    @Test fun successfulAuthenticatedRetryPublishesAcceptedConfigExactlyOnce() {
        val retry = byteArrayOf(7, 6, 5, 4)
        val accepted = mutableListOf<ByteArray>()
        val backend = QueueBackend(
            EchCapability.CONSCRYPT,
            mutableListOf(EchConnectResult.Retry(retry), EchConnectResult.Connected(fakeSocket())),
        )
        val result = EchTlsCoordinator(
            backend = backend,
            onAuthenticatedRetryAccepted = { accepted += it },
        ).connect(EchMode.REQUIRED, request)
        assertTrue(result is EchConnectResult.Connected)
        assertEquals(1, accepted.size)
        assertArrayEquals(retry, accepted.single())
        assertEquals(2, backend.requests.size)
        assertArrayEquals(retry, backend.requests[1].configList)
    }

    @Test fun failedAuthenticatedRetryDoesNotPublishSeedRenewal() {
        val retry = byteArrayOf(3, 2, 1)
        val accepted = mutableListOf<ByteArray>()
        val backend = QueueBackend(
            EchCapability.CONSCRYPT,
            mutableListOf(EchConnectResult.Retry(retry), EchConnectResult.Failed(SSLException("retry failed"))),
        )
        val result = EchTlsCoordinator(
            backend = backend,
            onAuthenticatedRetryAccepted = { accepted += it },
        ).connect(EchMode.REQUIRED, request)
        assertTrue(result is EchConnectResult.Failed)
        assertTrue(accepted.isEmpty())
    }

    @Test fun persistenceCallbackFailureCannotBreakAuthenticatedTunnel() {
        val retry = byteArrayOf(8, 8, 8)
        val backend = QueueBackend(
            EchCapability.CONSCRYPT,
            mutableListOf(EchConnectResult.Retry(retry), EchConnectResult.Connected(fakeSocket())),
        )
        val result = EchTlsCoordinator(
            backend = backend,
            onAuthenticatedRetryAccepted = { error("persistence unavailable") },
        ).connect(EchMode.REQUIRED, request)
        assertTrue(result is EchConnectResult.Connected)
    }

    private fun fakeSocket(): SSLSocket =
        SSLSocketFactory.getDefault().createSocket() as SSLSocket

    private class QueueBackend(
        override val capability: EchCapability,
        private val results: MutableList<EchConnectResult>,
    ) : EchTlsBackend {
        val requests = mutableListOf<EchConnectRequest>()
        override fun connect(request: EchConnectRequest): EchConnectResult {
            requests += request
            return results.removeAt(0)
        }
    }
}
