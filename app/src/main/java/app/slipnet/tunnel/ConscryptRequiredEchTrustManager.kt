package app.slipnet.tunnel

import org.conscrypt.DomainEncryptionMode
import org.conscrypt.NetworkSecurityPolicy
import org.conscrypt.metrics.CertificateTransparencyVerificationReason
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager

class ConscryptRequiredEchTrustManager(
    private val delegate: X509TrustManager,
) : X509TrustManager {
    fun getNetworkSecurityPolicy(): NetworkSecurityPolicy = object : NetworkSecurityPolicy {
        override fun isCertificateTransparencyVerificationRequired(hostname: String?) = false
        override fun getCertificateTransparencyVerificationReason(hostname: String?) =
            CertificateTransparencyVerificationReason.UNKNOWN
        override fun getDomainEncryptionMode(hostname: String?) = DomainEncryptionMode.REQUIRED
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
        delegate.checkClientTrusted(chain, authType)
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) =
        delegate.checkServerTrusted(chain, authType)
}
