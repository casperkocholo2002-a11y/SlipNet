package mobile;

public class DnsttClient {
    public void setAuthoritativeMode(boolean value) {}
    public void setMaxPayload(long value) {}
    public void setNoizMode(boolean value) {}
    public void setDeviceManufacturer(String value) {}
    public void setStealthMode(boolean value) {}
    public void setSOCKS5Proxy(String addr, String user, String pass) {}
    public void setResolverMode(String value) {}
    public void setRRSpreadCount(long value) {}
    public void start() { throw new UnsupportedOperationException("DNSTT disabled in personal build"); }
    public void stop() {}
    public boolean isRunning() { return false; }
}
