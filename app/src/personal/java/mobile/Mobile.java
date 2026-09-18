package mobile;

public final class Mobile {
    private Mobile() {}
    public static DnsttClient newClient(String dnsServer, String domain, String publicKey, String listenAddr) {
        throw new UnsupportedOperationException("DNSTT disabled in personal build");
    }
}
