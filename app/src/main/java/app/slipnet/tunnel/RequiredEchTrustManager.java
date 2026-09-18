package app.slipnet.tunnel;

import org.conscrypt.ConscryptNetworkSecurityPolicy;
import org.conscrypt.DomainEncryptionMode;
import org.conscrypt.NetworkSecurityPolicy;
import org.conscrypt.metrics.CertificateTransparencyVerificationReason;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

public final class RequiredEchTrustManager extends X509ExtendedTrustManager {
    private final X509TrustManager delegate;
    private final X509ExtendedTrustManager extended;
    private final NetworkSecurityPolicy basePolicy = ConscryptNetworkSecurityPolicy.getDefault();
    private final NetworkSecurityPolicy echPolicy = new NetworkSecurityPolicy() {
        @Override public boolean isCertificateTransparencyVerificationRequired(String host) {
            return basePolicy.isCertificateTransparencyVerificationRequired(host);
        }
        @Override public CertificateTransparencyVerificationReason getCertificateTransparencyVerificationReason(String host) {
            return basePolicy.getCertificateTransparencyVerificationReason(host);
        }
        @Override public DomainEncryptionMode getDomainEncryptionMode(String host) {
            return DomainEncryptionMode.REQUIRED;
        }
    };

    public RequiredEchTrustManager(X509TrustManager delegate) {
        this.delegate = delegate;
        this.extended = delegate instanceof X509ExtendedTrustManager
                ? (X509ExtendedTrustManager) delegate : null;
    }

    public NetworkSecurityPolicy getNetworkSecurityPolicy() {
        return echPolicy;
    }

    @Override public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
    }

    @Override public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }

    @Override public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        if (extended != null) extended.checkClientTrusted(chain, authType, socket);
        else delegate.checkClientTrusted(chain, authType);
    }

    @Override public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        if (extended != null) extended.checkServerTrusted(chain, authType, socket);
        else delegate.checkServerTrusted(chain, authType);
    }

    @Override public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        if (extended != null) extended.checkClientTrusted(chain, authType, engine);
        else delegate.checkClientTrusted(chain, authType);
    }

    @Override public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        if (extended != null) extended.checkServerTrusted(chain, authType, engine);
        else delegate.checkServerTrusted(chain, authType);
    }
}
