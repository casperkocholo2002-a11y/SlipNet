package vaydns;

public final class Vaydns {
    private Vaydns() {}
    public static VaydnsClient newClient(String dnsServer, String domain, String publicKey, String listenAddr) {
        throw new UnsupportedOperationException("VayDNS disabled in personal build");
    }
}
