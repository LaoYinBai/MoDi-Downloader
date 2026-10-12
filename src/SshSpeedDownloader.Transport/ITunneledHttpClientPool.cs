namespace SshSpeedDownloader.Transport;

public interface ITunneledHttpClientLease : IDisposable
{
    Guid TunnelId { get; }
    HttpClient HttpClient { get; }
}

public interface ITunneledHttpClientPool
{
    bool IsConnected { get; }
    int TunnelCount { get; }
    ITunneledHttpClientLease AcquireHttpClient();
    Task WaitUntilConnectedAsync(CancellationToken cancellationToken);
    Task<bool> TryAddSecondTunnelAsync(CancellationToken cancellationToken);
    Task RemoveSecondTunnelAsync();
}
