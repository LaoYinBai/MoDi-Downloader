namespace SshSpeedDownloader.Transport;

public enum TunnelState
{
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    HostKeyTrustRequired,
    Failed
}

public sealed record TunnelStatus(
    TunnelState State,
    string Message,
    int TunnelCount,
    int LocalSocksPort,
    string? HostFingerprint = null);

public sealed record ConnectionDiagnostic(string ServerIdentity, string EgressIp, int TunnelCount);

public sealed class TunnelUnavailableException(string message) : IOException(message);

public sealed class TunnelClientLease : ITunneledHttpClientLease
{
    private readonly Action _release;
    private int _disposed;

    internal TunnelClientLease(Guid tunnelId, HttpClient httpClient, Action release)
    {
        TunnelId = tunnelId;
        HttpClient = httpClient;
        _release = release;
    }

    public Guid TunnelId { get; }
    public HttpClient HttpClient { get; }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
            _release();
    }
}
