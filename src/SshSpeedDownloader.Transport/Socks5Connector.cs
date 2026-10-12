using System.Net;
using System.Net.Sockets;
using System.Globalization;
using System.Text;

namespace SshSpeedDownloader.Transport;

public sealed class Socks5ProtocolException(string message) : IOException(message);

public static class Socks5Connector
{
    public static async ValueTask<Stream> ConnectAsync(
        int loopbackProxyPort,
        DnsEndPoint destination,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (loopbackProxyPort is < 1 or > ushort.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(loopbackProxyPort));
        if (destination.Port is < 1 or > ushort.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(destination));

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(IPAddress.Loopback, loopbackProxyPort, cancellationToken).ConfigureAwait(false);
            var stream = new NetworkStream(socket, ownsSocket: true);
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, cancellationToken).ConfigureAwait(false);

            var method = new byte[2];
            await stream.ReadExactlyAsync(method, cancellationToken).ConfigureAwait(false);
            if (method[0] != 0x05 || method[1] != 0x00)
                throw new Socks5ProtocolException("The SSH SOCKS5 proxy did not accept unauthenticated local clients.");

            var address = CreateAddress(destination.Host);
            var request = new byte[4 + address.Bytes.Length + 2];
            request[0] = 0x05;
            request[1] = 0x01;
            request[2] = 0x00;
            request[3] = address.Type;
            address.Bytes.CopyTo(request, 4);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(
                request.AsSpan(request.Length - 2),
                (ushort)destination.Port);
            await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);

            var header = new byte[4];
            await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
            if (header[0] != 0x05 || header[2] != 0x00)
                throw new Socks5ProtocolException("The SSH SOCKS5 proxy returned a malformed response.");
            if (header[1] != 0x00)
                throw new Socks5ProtocolException($"The SSH SOCKS5 proxy could not connect to the target (reply {header[1]}).");

            var boundAddressLength = header[3] switch
            {
                0x01 => 4,
                0x04 => 16,
                0x03 => await ReadDomainLengthAsync(stream, cancellationToken).ConfigureAwait(false),
                _ => throw new Socks5ProtocolException("The SSH SOCKS5 proxy returned an unsupported address type.")
            };
            await stream.ReadExactlyAsync(new byte[boundAddressLength + 2], cancellationToken).ConfigureAwait(false);
            return stream;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static (byte Type, byte[] Bytes) CreateAddress(string host)
    {
        if (IPAddress.TryParse(host, out var ip))
            return ip.AddressFamily == AddressFamily.InterNetwork
                ? ((byte)0x01, ip.GetAddressBytes())
                : ((byte)0x04, ip.GetAddressBytes());

        var asciiHost = new IdnMapping().GetAscii(host.TrimEnd('.'));
        var bytes = Encoding.ASCII.GetBytes(asciiHost);
        if (bytes.Length is < 1 or > byte.MaxValue)
            throw new Socks5ProtocolException("The target host name is too long for SOCKS5.");
        return ((byte)0x03, [checked((byte)bytes.Length), .. bytes]);
    }

    private static async ValueTask<int> ReadDomainLengthAsync(Stream stream, CancellationToken cancellationToken)
    {
        var length = new byte[1];
        await stream.ReadExactlyAsync(length, cancellationToken).ConfigureAwait(false);
        return length[0];
    }
}
