using System.Net;
using System.Net.Sockets;
using System.Text;
using SshSpeedDownloader.Transport;

namespace SshSpeedDownloader.Tests;

public sealed class TunnelHttpClientTests
{
    [Fact]
    public async Task FailsClosedWhenTunnelIsUnavailableInsteadOfConnectingDirectly()
    {
        using var origin = new TcpListener(IPAddress.Loopback, 0);
        origin.Start();
        var originPort = ((IPEndPoint)origin.LocalEndpoint).Port;
        var directConnectionObserved = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var originCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var originTask = Task.Run(async () =>
        {
            try
            {
                using var socket = await origin.AcceptSocketAsync(originCancellation.Token);
                directConnectionObserved.TrySetResult();
                using var stream = new NetworkStream(socket, ownsSocket: false);
                await stream.WriteAsync(Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"), originCancellation.Token);
            }
            catch (OperationCanceledException)
            {
            }
        });

        using var occupied = new TcpListener(IPAddress.Loopback, 0);
        occupied.Start();
        var unavailableProxyPort = ((IPEndPoint)occupied.LocalEndpoint).Port;
        occupied.Stop();

        using var client = new Socks5HttpClientFactory(() => unavailableProxyPort).CreateClient();
        await Assert.ThrowsAnyAsync<HttpRequestException>(() =>
            client.GetAsync($"http://127.0.0.1:{originPort}/resource", CancellationToken.None));
        Assert.False(directConnectionObserved.Task.IsCompleted);
        await originTask;
    }
}
