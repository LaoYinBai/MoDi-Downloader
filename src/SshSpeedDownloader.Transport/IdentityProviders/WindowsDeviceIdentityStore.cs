using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Transport.IdentityProviders;

public sealed record DeviceRequestState(string? IdempotencyKey, string? RequestId);

public interface IDeviceIdentityStore
{
    Task<DeviceIdentity> LoadOrCreateAsync(CancellationToken cancellationToken = default);
    DeviceIdentity Device { get; }
    Stream OpenPrivateKeyStream();
    byte[] Sign(ReadOnlySpan<byte> canonicalRequest);
    Task<DeviceRequestState> LoadRequestStateAsync(CancellationToken cancellationToken = default);
    Task SaveRequestStateAsync(DeviceRequestState state, CancellationToken cancellationToken = default);
    Task ClearRequestStateAsync(CancellationToken cancellationToken = default);
    Task ForgetLocalIdentityAsync(CancellationToken cancellationToken = default);
}

[SupportedOSPlatform("windows")]
public sealed class WindowsDeviceIdentityStore : IDeviceIdentityStore
{
    private const int SchemaVersion = 1;
    private const int MaximumPrivateKeyBytes = 16 * 1024;
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("MoDiDownloader.DeviceIdentity.v1");
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private static readonly Regex IdempotencyPattern = new("^[0-9a-f]{32}$", RegexOptions.CultureInvariant);
    private static readonly Regex RequestIdPattern = new("^[0-9a-f]{32}$", RegexOptions.CultureInvariant);

    private readonly object _sync = new();
    private readonly string _statePath;
    private readonly string _displayName;
    private IdentityDocument? _document;
    private DeviceIdentity? _device;

    public WindowsDeviceIdentityStore(string statePath, string displayName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        if (!Path.IsPathFullyQualified(statePath))
            throw new ArgumentException("Identity state path must be absolute.", nameof(statePath));
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Downloader device identity storage requires Windows DPAPI.");

        _statePath = Path.GetFullPath(statePath);
        _displayName = NormalizeDisplayName(displayName);
    }

    public DeviceIdentity Device => _device ??
        throw new InvalidOperationException("Device identity has not been loaded.");

    public Task<DeviceIdentity> LoadOrCreateAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => LoadOrCreate(cancellationToken), cancellationToken);

    public Stream OpenPrivateKeyStream()
    {
        var document = GetLoadedDocument();
        var privateKeyBytes = UnprotectPrivateKey(document.ProtectedPrivateKey);
        char[] pemCharacters = [];
        byte[]? pemBytes = null;
        try
        {
            using var key = ImportPrivateKey(privateKeyBytes);
            pemCharacters = PemEncoding.Write("PRIVATE KEY", privateKeyBytes);
            pemBytes = Encoding.ASCII.GetBytes(pemCharacters);
            return new MemoryStream(pemBytes, 0, pemBytes.Length, writable: false, publiclyVisible: true);
        }
        catch
        {
            if (pemBytes is not null)
                CryptographicOperations.ZeroMemory(pemBytes);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKeyBytes);
            if (pemCharacters.Length > 0)
                Array.Clear(pemCharacters);
        }
    }

    public byte[] Sign(ReadOnlySpan<byte> canonicalRequest)
    {
        if (canonicalRequest.Length is < 1 or > 16 * 1024)
            throw new ArgumentException("Canonical device request is too large.", nameof(canonicalRequest));

        var document = GetLoadedDocument();
        var privateKeyBytes = UnprotectPrivateKey(document.ProtectedPrivateKey);
        try
        {
            using var key = ImportPrivateKey(privateKeyBytes);
            return key.SignData(
                canonicalRequest,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKeyBytes);
        }
    }

    public Task<DeviceRequestState> LoadRequestStateAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            var document = GetLoadedDocument();
            return new DeviceRequestState(document.IdempotencyKey, document.RequestId);
        }, cancellationToken);

    public Task SaveRequestStateAsync(
        DeviceRequestState state,
        CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            ArgumentNullException.ThrowIfNull(state);
            cancellationToken.ThrowIfCancellationRequested();
            if (state.IdempotencyKey is not null && !IdempotencyPattern.IsMatch(state.IdempotencyKey))
                throw new ArgumentException("Request idempotency key is invalid.", nameof(state));
            if (state.RequestId is not null && !RequestIdPattern.IsMatch(state.RequestId))
                throw new ArgumentException("Request ID is invalid.", nameof(state));
            if (state.RequestId is not null && state.IdempotencyKey is null)
                throw new ArgumentException("A request ID must retain its idempotency key.", nameof(state));

            lock (_sync)
            {
                var document = _document ?? throw new InvalidOperationException("Device identity has not been loaded.");
                var updated = document with
                {
                    IdempotencyKey = state.IdempotencyKey,
                    RequestId = state.RequestId
                };
                WriteDocument(updated);
                _document = updated;
            }
        }, cancellationToken);

    public Task ClearRequestStateAsync(CancellationToken cancellationToken = default) =>
        SaveRequestStateAsync(new DeviceRequestState(null, null), cancellationToken);

    public Task ForgetLocalIdentityAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_sync)
            {
                if (File.Exists(_statePath))
                    File.Delete(_statePath);
                _document = null;
                _device = null;
            }
        }, cancellationToken);

    private DeviceIdentity LoadOrCreate(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            if (_device is not null)
                return _device;
            if (File.Exists(_statePath))
            {
                try
                {
                    var text = File.ReadAllText(_statePath, Encoding.UTF8);
                    var document = JsonSerializer.Deserialize<IdentityDocument>(text, JsonOptions)
                        ?? throw new InvalidDataException("Stored device identity is empty.");
                    ValidateDocument(document);
                    _document = document;
                    _device = CreateDevice(document);
                    return _device;
                }
                catch (Exception exception) when (exception is JsonException or FormatException or CryptographicException or ArgumentException or InvalidOperationException)
                {
                    throw new InvalidDataException("Stored device identity is corrupt or unavailable; it was not replaced.", exception);
                }
            }

            Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var privateKeyBytes = key.ExportPkcs8PrivateKey();
            byte[] protectedBytes;
            try
            {
                protectedBytes = ProtectedData.Protect(
                    privateKeyBytes,
                    Entropy,
                    DataProtectionScope.CurrentUser);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKeyBytes);
            }

            try
            {
                var publicKey = OpenSshP256KeyCodec.ExportPublicKey(key, "modi-downloader");
                var document = new IdentityDocument
                {
                    SchemaVersion = SchemaVersion,
                    DeviceId = DeviceIdFactory.Create(),
                    DisplayName = _displayName,
                    PublicKey = publicKey,
                    PublicKeyFingerprint = OpenSshP256KeyCodec.Fingerprint(publicKey),
                    ProtectedPrivateKey = Convert.ToBase64String(protectedBytes)
                };
                ValidateDocument(document);
                WriteDocument(document);
                _document = document;
                _device = CreateDevice(document);
                return _device;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
        }
    }

    private void ValidateDocument(IdentityDocument document)
    {
        if (document.SchemaVersion != SchemaVersion ||
            !DeviceIdFactory.IsValid(document.DeviceId) ||
            !IsValidDisplayName(document.DisplayName) ||
            string.IsNullOrWhiteSpace(document.PublicKey) ||
            string.IsNullOrWhiteSpace(document.ProtectedPrivateKey) ||
            document.PublicKeyFingerprint != OpenSshP256KeyCodec.Fingerprint(document.PublicKey) ||
            (document.IdempotencyKey is not null && !IdempotencyPattern.IsMatch(document.IdempotencyKey)) ||
            (document.RequestId is not null && !RequestIdPattern.IsMatch(document.RequestId)) ||
            (document.RequestId is not null && document.IdempotencyKey is null))
        {
            throw new InvalidDataException("Stored device identity fields are invalid.");
        }

        var privateKeyBytes = UnprotectPrivateKey(document.ProtectedPrivateKey);
        try
        {
            using var key = ImportPrivateKey(privateKeyBytes);
            var publicKey = OpenSshP256KeyCodec.ExportPublicKey(key, "modi-downloader");
            if (!StringComparer.Ordinal.Equals(
                    OpenSshP256KeyCodec.Fingerprint(publicKey),
                    document.PublicKeyFingerprint))
                throw new InvalidDataException("Stored device public and private keys do not match.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKeyBytes);
        }
    }

    private static DeviceIdentity CreateDevice(IdentityDocument document) =>
        new(document.DeviceId, document.DisplayName, document.PublicKey, document.PublicKeyFingerprint);

    private IdentityDocument GetLoadedDocument() =>
        _document ?? throw new InvalidOperationException("Device identity has not been loaded.");

    private static byte[] UnprotectPrivateKey(string protectedPrivateKey)
    {
        byte[] protectedBytes;
        try
        {
            protectedBytes = Convert.FromBase64String(protectedPrivateKey);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("Stored device key is invalid.", exception);
        }

        try
        {
            var privateKey = ProtectedData.Unprotect(
                protectedBytes,
                Entropy,
                DataProtectionScope.CurrentUser);
            if (privateKey.Length is < 1 or > MaximumPrivateKeyBytes)
            {
                CryptographicOperations.ZeroMemory(privateKey);
                throw new InvalidDataException("Stored device key has an invalid length.");
            }
            return privateKey;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    private static ECDsa ImportPrivateKey(byte[] privateKeyBytes)
    {
        var key = ECDsa.Create();
        try
        {
            key.ImportPkcs8PrivateKey(privateKeyBytes, out var bytesRead);
            if (bytesRead != privateKeyBytes.Length || key.KeySize != 256)
                throw new InvalidDataException("Stored device key is not a P-256 key.");
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    private void WriteDocument(IdentityDocument document)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);
        var temporaryPath = _statePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, document, JsonOptions);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, _statePath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
        }
    }

    private static string NormalizeDisplayName(string? displayName)
    {
        var normalized = new string((displayName ?? "")
            .Where(character => !char.IsControl(character) &&
                character is not '<' and not '>' and not '&' and not '\u2028' and not '\u2029')
            .Take(64)
            .ToArray())
            .Trim();
        return normalized.Length == 0 ? "Windows Downloader" : normalized;
    }

    private static bool IsValidDisplayName(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 64 &&
        !value.Any(char.IsControl);

    private sealed record IdentityDocument
    {
        public int SchemaVersion { get; init; }
        public string DeviceId { get; init; } = "";
        public string DisplayName { get; init; } = "";
        public string PublicKey { get; init; } = "";
        public string PublicKeyFingerprint { get; init; } = "";
        public string ProtectedPrivateKey { get; init; } = "";
        public string? IdempotencyKey { get; init; }
        public string? RequestId { get; init; }
    }
}

public static class OpenSshP256KeyCodec
{
    private static readonly byte[] Algorithm = Encoding.ASCII.GetBytes("ecdsa-sha2-nistp256");
    private static readonly byte[] Curve = Encoding.ASCII.GetBytes("nistp256");
    private static readonly string ExpectedCurveOid = ECCurve.NamedCurves.nistP256.Oid.Value!;

    public static string ExportPublicKey(ECDsa key, string comment)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeySize != 256)
            throw new ArgumentException("A P-256 key is required.", nameof(key));
        if (string.IsNullOrWhiteSpace(comment) || comment.Length > 128 || comment.Any(char.IsControl))
            throw new ArgumentException("Public-key comment is invalid.", nameof(comment));

        var parameters = key.ExportParameters(includePrivateParameters: false);
        if (!StringComparer.Ordinal.Equals(parameters.Curve.Oid.Value, ExpectedCurveOid) ||
            parameters.Q.X is not { Length: 32 } x ||
            parameters.Q.Y is not { Length: 32 } y)
            throw new ArgumentException("A NIST P-256 key is required.", nameof(key));

        var point = new byte[65];
        point[0] = 4;
        x.CopyTo(point, 1);
        y.CopyTo(point, 33);
        using var blob = new MemoryStream();
        WriteSshString(blob, Algorithm);
        WriteSshString(blob, Curve);
        WriteSshString(blob, point);
        CryptographicOperations.ZeroMemory(point);
        var keyBlob = blob.ToArray();
        try
        {
            return $"ecdsa-sha2-nistp256 {Convert.ToBase64String(keyBlob)} {comment}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBlob);
        }
    }

    public static string Fingerprint(string publicKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(publicKey);
        if (publicKey.Length > 4096)
            throw new ArgumentException("OpenSSH public key is too large.", nameof(publicKey));
        var fields = publicKey.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length is < 2 or > 3 || fields[0] != "ecdsa-sha2-nistp256")
            throw new ArgumentException("Only OpenSSH ECDSA P-256 keys are supported.", nameof(publicKey));

        byte[] keyBlob;
        try
        {
            keyBlob = Convert.FromBase64String(fields[1]);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("OpenSSH public key is malformed.", nameof(publicKey), exception);
        }

        try
        {
            var offset = 0;
            var algorithm = ReadSshString(keyBlob, ref offset);
            var curve = ReadSshString(keyBlob, ref offset);
            var point = ReadSshString(keyBlob, ref offset);
            if (offset != keyBlob.Length ||
                !algorithm.AsSpan().SequenceEqual(Algorithm) ||
                !curve.AsSpan().SequenceEqual(Curve) ||
                point.Length != 65 ||
                point[0] != 4)
                throw new ArgumentException("OpenSSH P-256 public key is malformed.", nameof(publicKey));

            using var validatedKey = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = point.AsSpan(1, 32).ToArray(),
                    Y = point.AsSpan(33, 32).ToArray()
                }
            });
            var digest = SHA256.HashData(keyBlob);
            try
            {
                return "SHA256:" + Convert.ToBase64String(digest).TrimEnd('=');
            }
            finally
            {
                CryptographicOperations.ZeroMemory(digest);
            }
        }
        catch (ArgumentException)
        {
            throw;
        }
        catch (Exception exception) when (exception is CryptographicException or OverflowException)
        {
            throw new ArgumentException("OpenSSH P-256 public key is invalid.", nameof(publicKey), exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBlob);
        }
    }

    private static void WriteSshString(Stream destination, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        destination.Write(length);
        destination.Write(value);
    }

    private static byte[] ReadSshString(ReadOnlySpan<byte> blob, ref int offset)
    {
        if (offset + 4 > blob.Length)
            throw new ArgumentException("OpenSSH key blob is truncated.");
        var length = BinaryPrimitives.ReadUInt32BigEndian(blob.Slice(offset, 4));
        offset += 4;
        if (length > 4096 || offset + length > blob.Length)
            throw new ArgumentException("OpenSSH key blob has an invalid length.");
        var result = blob.Slice(offset, (int)length).ToArray();
        offset += (int)length;
        return result;
    }
}
