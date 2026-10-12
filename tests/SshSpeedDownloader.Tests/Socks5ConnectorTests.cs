using System.Net;
using System.Net.Sockets;
using System.Text;
using SshSpeedDownloader.Transport;

namespace SshSpeedDownloader.Tests;

public sealed class Socks5ConnectorTests
{
    [Fact]
    public async Task OpensOnlyTheLoopbackProxyAndSendsTargetAsRemoteDnsName()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var proxyPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var observed = new TaskCompletionSource<(string Host, int Port)>(TaskCreationOptions.RunContinuationsAsynchronously);

        var server = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync();
            using var stream = new NetworkStream(socket, ownsSocket: false);
            Assert.Equal(new byte[] { 5, 1, 0 }, await ReadExactlyAsync(stream, 3));
            await stream.WriteAsync(new byte[] { 5, 0 });

            var header = await ReadExactlyAsync(stream, 5);
            Assert.Equal(new byte[] { 5, 1, 0, 3 }, header[..4]);
            var host = Encoding.ASCII.GetString(await ReadExactlyAsync(stream, header[4]));
            var port = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(await ReadExactlyAsync(stream, 2));
            observed.TrySetResult((host, port));
            await stream.WriteAsync(new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 });

            var marker = await ReadExactlyAsync(stream, 1);
            await stream.WriteAsync(new[] { (byte)(marker[0] + 1) });
        });

        await using var tunneled = await Socks5Connector.ConnectAsync(
            proxyPort,
            new DnsEndPoint("example.com", 443),
            CancellationToken.None);

        Assert.Equal(("example.com", 443), await observed.Task.WaitAsync(TimeSpan.FromSeconds(3)));
        await tunneled.WriteAsync(new byte[] { 42 });
        Assert.Equal(new byte[] { 43 }, await ReadExactlyAsync(tunneled, 1));
        await server.WaitAsync(TimeSpan.FromSeconds(3));
    }

    private static async Task<byte[]> ReadExactlyAsync(Stream stream, int count)
    {
        var result = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(result.AsMemory(offset));
            if (read == 0)
                throw new EndOfStreamException();
            offset += read;
        }

        return result;
    }
}
