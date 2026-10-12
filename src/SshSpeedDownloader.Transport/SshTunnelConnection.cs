using Renci.SshNet;
using Renci.SshNet.Common;
using System.Security.Cryptography;
using System.Reflection;
using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Transport;

public sealed class HostKeyTrustRequiredException(string fingerprint, bool changedExistingPin)
    : Exception("The SSH host key needs explicit user approval.")
{
    public string Fingerprint { get; } = fingerprint;
    public bool ChangedExistingPin { get; } = changedExistingPin;
}

public sealed class PrivateKeyPassphraseRequiredException()
    : Exception("The private key requires a passphrase stored in Windows Credential Manager.");

public sealed class PrivateKeyUnlockFailedException()
    : Exception("The private key could not be unlocked with the stored passphrase.");

public sealed class SshTunnelConnection : IAsyncDisposable
{
    private readonly SshClient _client;
    private readonly ForwardedPortDynamic _forwardedPort;
    private readonly PrivateKeyFile _privateKey;
    private readonly Stream? _privateKeyStream;
    private readonly HttpClient _httpClient;
    private int _disposed;

    private SshTunnelConnection(
        SshClient client,
        ForwardedPortDynamic forwardedPort,
        PrivateKeyFile privateKey,
        Stream? privateKeyStream,
        HttpClient httpClient,
        string hostFingerprint)
    {
        _client = client;
        _forwardedPort = forwardedPort;
        _privateKey = privateKey;
        _privateKeyStream = privateKeyStream;
        _httpClient = httpClient;
        HostFingerprint = hostFingerprint;
    }

    public Guid Id { get; } = Guid.NewGuid();
    public int SocksPort => checked((int)_forwardedPort.BoundPort);
    public string HostFingerprint { get; }
    public bool IsConnected => Volatile.Read(ref _disposed) == 0 && _client.IsConnected && _forwardedPort.IsStarted;
    public HttpClient HttpClient => _httpClient;

    public event EventHandler? ConnectionFaulted;

    public static async Task<SshTunnelConnection> OpenAsync(
        SshConnectionProfile profile,
        string? passphrase,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (!SshConnectionProfileValidator.TryValidate(profile, out var validationError))
            throw new ArgumentException(validationError, nameof(profile));

        Stream? privateKeyStream = null;
        PrivateKeyFile key;
        try
        {
            if (profile.PrivateKeyStreamProvider is { } streamProvider)
            {
                privateKeyStream = streamProvider();
                key = new PrivateKeyFile(privateKeyStream, passphrase);
            }
            else
                key = new PrivateKeyFile(profile.PrivateKeyPath, passphrase);
        }
        catch (SshPassPhraseNullOrEmptyException)
        {
            DisposeEmbeddedKeyStream(privateKeyStream);
            throw new PrivateKeyPassphraseRequiredException();
        }
        catch (SshException)
        {
            DisposeEmbeddedKeyStream(privateKeyStream);
            throw new PrivateKeyUnlockFailedException();
        }
        catch
        {
            DisposeEmbeddedKeyStream(privateKeyStream);
            throw;
        }
        var authentication = new PrivateKeyAuthenticationMethod(profile.Username, key);
        var connectionInfo = new ConnectionInfo(profile.Host, profile.Port, profile.Username, authentication)
        {
            Timeout = TimeSpan.FromSeconds(15)
        };
        var client = new SshClient(connectionInfo)
        {
            KeepAliveInterval = TimeSpan.FromSeconds(15)
        };

        string? receivedFingerprint = null;
        client.HostKeyReceived += (_, args) =>
        {
            receivedFingerprint = $"SHA256:{args.FingerPrintSHA256}";
            args.CanTrust = HostKeyPin.Matches(args.FingerPrintSHA256, profile);
        };

        try
        {
            await client.ConnectAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            client.Dispose();
            key.Dispose();
            DisposeEmbeddedKeyStream(privateKeyStream);
            if (receivedFingerprint is not null &&
                !HostKeyPin.Matches(receivedFingerprint, profile))
                throw new HostKeyTrustRequiredException(
                    receivedFingerprint,
                    profile.TrustedHostFingerprint is not null || profile.TrustedHostFingerprints.Count > 0);
            throw;
        }

        if (receivedFingerprint is null || !HostKeyPin.Matches(receivedFingerprint, profile))
        {
            client.Dispose();
            key.Dispose();
            DisposeEmbeddedKeyStream(privateKeyStream);
            throw new HostKeyTrustRequiredException(
                receivedFingerprint ?? "指纹不可用",
                profile.TrustedHostFingerprint is not null || profile.TrustedHostFingerprints.Count > 0);
        }

        var forwardedPort = new ForwardedPortDynamic("127.0.0.1", 0);
        try
        {
            client.AddForwardedPort(forwardedPort);
            forwardedPort.Start();
            if (!forwardedPort.IsStarted || forwardedPort.BoundPort is 0 or > ushort.MaxValue)
                throw new IOException("The local SOCKS5 listener did not start.");

            var factory = new Socks5HttpClientFactory(() => checked((int)forwardedPort.BoundPort));
            var httpClient = factory.CreateClient();
            var connection = new SshTunnelConnection(client, forwardedPort, key, privateKeyStream, httpClient, receivedFingerprint);
            client.ErrorOccurred += connection.Client_ErrorOccurred;
            forwardedPort.Exception += connection.Port_Exception;
            return connection;
        }
        catch
        {
            forwardedPort.Dispose();
            client.Dispose();
            key.Dispose();
            DisposeEmbeddedKeyStream(privateKeyStream);
            throw;
        }
    }

    public async Task<string> ReadServerIdentityAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (!_client.IsConnected)
            throw new InvalidOperationException("The SSH connection is not available.");

        using var command = _client.CreateCommand("hostname && uptime");
        command.CommandTimeout = TimeSpan.FromSeconds(12);
        await command.ExecuteAsync(cancellationToken).ConfigureAwait(false);
        if (command.ExitStatus != 0)
            throw new IOException("The read-only SSH connection test returned a non-zero exit status.");
        return command.Result.Trim();
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        _httpClient.Dispose();
        try
        {
            _forwardedPort.Stop();
        }
        catch
        {
        }

        try
        {
            if (_client.IsConnected)
                _client.Disconnect();
        }
        catch
        {
        }

        _forwardedPort.Dispose();
        _client.Dispose();
        _privateKey.Dispose();
        DisposeEmbeddedKeyStream(_privateKeyStream);
        await ValueTask.CompletedTask;
    }

    private void Client_ErrorOccurred(object? sender, Renci.SshNet.Common.ExceptionEventArgs args) =>
        ConnectionFaulted?.Invoke(this, EventArgs.Empty);

    private void Port_Exception(object? sender, Renci.SshNet.Common.ExceptionEventArgs args) =>
        ConnectionFaulted?.Invoke(this, EventArgs.Empty);

    private static void DisposeEmbeddedKeyStream(Stream? stream)
    {
        if (stream is null)
            return;
        if (stream is MemoryStream memoryStream && memoryStream.TryGetBuffer(out var buffer))
            CryptographicOperations.ZeroMemory(buffer.AsSpan());
        stream.Dispose();
    }
}
