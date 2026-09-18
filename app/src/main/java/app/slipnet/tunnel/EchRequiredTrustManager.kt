package app.slipnet.tunnel

import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedTrustManager
import javax.net.ssl.X509TrustManager
import org.conscrypt.DomainEncryptionMode
import org.conscrypt.NetworkSecurityPolicy
import org.conscrypt.metrics.CertificateTransparencyVerificationReason

internal class EchRequiredTrustManager(
    private val delegate: X509TrustManager,
) : X509ExtendedTrustManager() {

    private val policy = object : NetworkSecurityPolicy {
        override fun isCertificateTransparencyVerificationRequired(hostname: String?): Boolean = false

        override fun getCertificateTransparencyVerificationReason(
            hostname: String?
        ): CertificateTransparencyVerificationReason = CertificateTransparencyVerificationReason.UNKNOWN

        override fun getDomainEncryptionMode(hostname: String?): DomainEncryptionMode =
            DomainEncryptionMode.REQUIRED
    }

    @Suppress("unused")
    fun getNetworkSecurityPolicy(): NetworkSecurityPolicy = policy

    override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
        delegate.checkClientTrusted(chain, authType)

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) =
        delegate.checkServerTrusted(chain, authType)

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket) {
        val extended = delegate as? X509ExtendedTrustManager
        if (extended != null) extended.checkClientTrusted(chain, authType, socket)
        else delegate.checkClientTrusted(chain, authType)
    }

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket) {
        val extended = delegate as? X509ExtendedTrustManager
        if (extended != null) extended.checkServerTrusted(chain, authType, socket)
        else delegate.checkServerTrusted(chain, authType)
    }

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine) {
        val extended = delegate as? X509ExtendedTrustManager
        if (extended != null) extended.checkClientTrusted(chain, authType, engine)
        else delegate.checkClientTrusted(chain, authType)
    }

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine) {
        val extended = delegate as? X509ExtendedTrustManager
        if (extended != null) extended.checkServerTrusted(chain, authType, engine)
        else delegate.checkServerTrusted(chain, authType)
    }
}
