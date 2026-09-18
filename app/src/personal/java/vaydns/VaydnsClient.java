package vaydns;

public class VaydnsClient {
    public void setDnsttCompat(boolean value) {}
    public void setMaxPayload(long value) {}
    public void setRecordType(String value) {}
    public void setMaxQnameLen(long value) {}
    public void setRPS(double value) {}
    public void setIdleTimeout(long value) {}
    public void setKeepAlive(long value) {}
    public void setUDPTimeout(long value) {}
    public void setMaxNumLabels(long value) {}
    public void setClientIDSize(long value) {}
    public void setResolverMode(String value) {}
    public void setRRSpreadCount(long value) {}
    public void start() { throw new UnsupportedOperationException("VayDNS disabled in personal build"); }
    public void stop() {}
    public boolean isRunning() { return false; }
}
