using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Transport.IdentityProviders;

[SupportedOSPlatform("windows")]
public sealed class WindowsDeviceIdentityStore : IDeviceIdentityStore
{
    private const int CurrentFormatVersion = 1;
    private const string IdentityFileName = "identity.json";
    private const string Algorithm = "ecdsa-sha2-nistp256";
    private const string CurveName = "nistp256";
    private const string P256Oid = "1.2.840.10045.3.1.7";
    private static readonly byte[] OptionalEntropy = Encoding.UTF8.GetBytes("MoDiDownloader.DeviceIdentity.v1");
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 8,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly string _identityDirectory;
    private readonly string _identityPath;
    private readonly string _displayName;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public WindowsDeviceIdentityStore(string? identityDirectory = null, string displayName = "MoDi Downloader Desktop")
    {
        EnsureWindows();
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        if (displayName.Trim().Length > 80 || displayName.Any(char.IsControl))
            throw new ArgumentException("Device display name is invalid.", nameof(displayName));

        var defaultDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "MoDiDownloader",
            "identity");
        _identityDirectory = Path.GetFullPath(identityDirectory ?? defaultDirectory);
        _identityPath = Path.Combine(_identityDirectory, IdentityFileName);
        _displayName = displayName.Trim();
    }

    public async Task<LocalDeviceIdentity> LoadOrCreateAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureWindows();
            Directory.CreateDirectory(_identityDirectory);
            return IdentityFileExists() ? LoadExisting() : CreateAndPersist();
        }
        catch (DeviceIdentityStoreException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new DeviceIdentityStoreException("The local device identity could not be loaded or created.", exception);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> ForgetLocalIdentityAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureWindows();
            if (!IdentityFileExists()) return false;
            File.Delete(_identityPath);
            return true;
        }
        catch (DeviceIdentityStoreException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new DeviceIdentityStoreException("The local device identity could not be removed.", exception);
        }
        finally
        {
            _gate.Release();
        }
    }

    private LocalDeviceIdentity CreateAndPersist()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var randomBytes = RandomNumberGenerator.GetBytes(16);
        byte[]? privateDer = null;
        byte[]? privatePem = null;
        byte[]? protectedPrivateKey = null;
        byte[]? serialized = null;
        string? temporaryPath = null;
        try
        {
            var deviceId = DeviceIdFactory.Create(randomBytes);
            var (publicKey, fingerprint) = CreateOpenSshPublicKey(key);
            privateDer = key.ExportPkcs8PrivateKey();
            privatePem = PemEncoding.WriteUtf8("PRIVATE KEY"u8, privateDer);
            protectedPrivateKey = ProtectedData.Protect(
                privatePem,
                OptionalEntropy,
                DataProtectionScope.CurrentUser);
            var persisted = new PersistedIdentity(
                CurrentFormatVersion,
                deviceId,
                _displayName,
                publicKey,
                fingerprint,
                Convert.ToBase64String(protectedPrivateKey));
            serialized = JsonSerializer.SerializeToUtf8Bytes(persisted, JsonOptions);
            temporaryPath = Path.Combine(_identityDirectory, $".{IdentityFileName}.{Guid.NewGuid():N}.tmp");

            using (var output = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                output.Write(serialized);
                output.Flush(flushToDisk: true);
            }

            try
            {
                File.Move(temporaryPath, _identityPath);
                temporaryPath = null;
            }
            catch (IOException) when (IdentityFileExists())
            {
                return LoadExisting();
            }

            return CreateLocalIdentity(persisted);
        }
        catch (Exception exception) when (exception is not DeviceIdentityStoreException)
        {
            throw new DeviceIdentityStoreException("A protected local device identity could not be created.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(randomBytes);
            if (privateDer is not null) CryptographicOperations.ZeroMemory(privateDer);
            if (privatePem is not null) CryptographicOperations.ZeroMemory(privatePem);
            if (protectedPrivateKey is not null) CryptographicOperations.ZeroMemory(protectedPrivateKey);
            if (serialized is not null) CryptographicOperations.ZeroMemory(serialized);
            if (temporaryPath is not null && File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private LocalDeviceIdentity LoadExisting()
    {
        byte[]? serialized = null;
        byte[]? protectedPrivateKey = null;
        byte[]? privatePem = null;
        try
        {
            serialized = File.ReadAllBytes(_identityPath);
            var persisted = JsonSerializer.Deserialize<PersistedIdentity>(serialized, JsonOptions)
                ?? throw new DeviceIdentityStoreException("Stored device identity metadata is invalid.");
            if (persisted.Version != CurrentFormatVersion || !DeviceIdFactory.IsValid(persisted.DeviceId) ||
                string.IsNullOrWhiteSpace(persisted.DisplayName) || persisted.DisplayName.Length > 80 ||
                persisted.DisplayName.Any(char.IsControl))
            {
                throw new DeviceIdentityStoreException("Stored device identity metadata is unsupported or invalid.");
            }

            _ = new DeviceIdentity(
                persisted.DeviceId,
                persisted.DisplayName,
                persisted.OpenSshPublicKey,
                persisted.PublicKeyFingerprint);
            protectedPrivateKey = Convert.FromBase64String(persisted.ProtectedPrivateKeyBase64);
            privatePem = ProtectedData.Unprotect(
                protectedPrivateKey,
                OptionalEntropy,
                DataProtectionScope.CurrentUser);
            ValidatePrivateKeyMatchesPublicKey(privatePem, persisted.OpenSshPublicKey);
            return CreateLocalIdentity(persisted);
        }
        catch (DeviceIdentityStoreException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new DeviceIdentityStoreException(
                "Stored device identity is corrupt or cannot be unprotected; it was not replaced.", exception);
        }
        finally
        {
            if (serialized is not null) CryptographicOperations.ZeroMemory(serialized);
            if (protectedPrivateKey is not null) CryptographicOperations.ZeroMemory(protectedPrivateKey);
            if (privatePem is not null) CryptographicOperations.ZeroMemory(privatePem);
        }
    }

    private LocalDeviceIdentity CreateLocalIdentity(PersistedIdentity persisted)
    {
        var device = new DeviceIdentity(
            persisted.DeviceId,
            persisted.DisplayName,
            persisted.OpenSshPublicKey,
            persisted.PublicKeyFingerprint);
        return new LocalDeviceIdentity(device, () => OpenPrivateKeyStream(device));
    }

    private Stream OpenPrivateKeyStream(DeviceIdentity expectedIdentity)
    {
        EnsureWindows();
        byte[]? serialized = null;
        byte[]? protectedPrivateKey = null;
        byte[]? privatePem = null;
        try
        {
            serialized = File.ReadAllBytes(_identityPath);
            var persisted = JsonSerializer.Deserialize<PersistedIdentity>(serialized, JsonOptions)
                ?? throw new DeviceIdentityStoreException("Stored device identity metadata is invalid.");
            if (persisted.Version != CurrentFormatVersion ||
                !StringComparer.Ordinal.Equals(persisted.DeviceId, expectedIdentity.DeviceId) ||
                !StringComparer.Ordinal.Equals(persisted.PublicKeyFingerprint, expectedIdentity.PublicKeyFingerprint))
            {
                throw new DeviceIdentityStoreException("Stored device identity changed after it was loaded.");
            }

            protectedPrivateKey = Convert.FromBase64String(persisted.ProtectedPrivateKeyBase64);
            privatePem = ProtectedData.Unprotect(
                protectedPrivateKey,
                OptionalEntropy,
                DataProtectionScope.CurrentUser);
            ValidatePrivateKeyMatchesPublicKey(privatePem, expectedIdentity.PublicKey);
            var stream = new ZeroingMemoryStream(privatePem);
            privatePem = null;
            return stream;
        }
        catch (DeviceIdentityStoreException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new DeviceIdentityStoreException("The device private key could not be opened.", exception);
        }
        finally
        {
            if (serialized is not null) CryptographicOperations.ZeroMemory(serialized);
            if (protectedPrivateKey is not null) CryptographicOperations.ZeroMemory(protectedPrivateKey);
            if (privatePem is not null) CryptographicOperations.ZeroMemory(privatePem);
        }
    }

    private bool IdentityFileExists()
    {
        try
        {
            var attributes = File.GetAttributes(_identityPath);
            if ((attributes & FileAttributes.Directory) != 0)
                throw new DeviceIdentityStoreException("The stored identity path is not a file.");
            return true;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
    }

    private static (string PublicKey, string Fingerprint) CreateOpenSshPublicKey(ECDsa key)
    {
        var parameters = key.ExportParameters(includePrivateParameters: false);
        var point = new byte[65];
        point[0] = 0x04;
        parameters.Q.X!.CopyTo(point, 1);
        parameters.Q.Y!.CopyTo(point, 33);
        using var blob = new MemoryStream();
        WriteSshString(blob, Encoding.ASCII.GetBytes(Algorithm));
        WriteSshString(blob, Encoding.ASCII.GetBytes(CurveName));
        WriteSshString(blob, point);
        CryptographicOperations.ZeroMemory(point);
        var keyBlob = blob.ToArray();
        var fingerprint = $"SHA256:{Convert.ToBase64String(SHA256.HashData(keyBlob)).TrimEnd('=')}";
        var publicKey = $"{Algorithm} {Convert.ToBase64String(keyBlob)} MoDiDownloader";
        CryptographicOperations.ZeroMemory(keyBlob);
        return (publicKey, fingerprint);
    }

    private static void ValidatePrivateKeyMatchesPublicKey(ReadOnlySpan<byte> privatePem, string openSshPublicKey)
    {
        var parsed = ParseOpenSshPublicKey(openSshPublicKey);
        var privateChars = new char[Encoding.UTF8.GetCharCount(privatePem)];
        _ = Encoding.UTF8.GetChars(privatePem, privateChars);
        try
        {
            using var key = ECDsa.Create();
            key.ImportFromPem(privateChars);
            var curve = key.ExportParameters(includePrivateParameters: false).Curve.Oid.Value;
            var publicPoint = key.ExportParameters(includePrivateParameters: false).Q;
            if (key.KeySize != 256 || !StringComparer.Ordinal.Equals(curve, P256Oid) ||
                !publicPoint.X!.AsSpan().SequenceEqual(parsed.X) ||
                !publicPoint.Y!.AsSpan().SequenceEqual(parsed.Y))
            {
                throw new DeviceIdentityStoreException("Stored P-256 private key does not match its public key.");
            }
        }
        catch (DeviceIdentityStoreException)
        {
            throw;
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            throw new DeviceIdentityStoreException("Stored P-256 private key is malformed.", exception);
        }
        finally
        {
            Array.Clear(privateChars);
            CryptographicOperations.ZeroMemory(parsed.X);
            CryptographicOperations.ZeroMemory(parsed.Y);
        }
    }

    private static (byte[] X, byte[] Y) ParseOpenSshPublicKey(string publicKey)
    {
        var fields = publicKey.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 2 || !StringComparer.Ordinal.Equals(fields[0], Algorithm))
            throw new DeviceIdentityStoreException("Stored OpenSSH public key is not P-256.");

        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(fields[1]);
            if (!StringComparer.Ordinal.Equals(Convert.ToBase64String(blob), fields[1]))
                throw new FormatException();
        }
        catch (FormatException exception)
        {
            throw new DeviceIdentityStoreException("Stored OpenSSH public key is malformed.", exception);
        }

        var offset = 0;
        var algorithm = ReadSshText(blob, ref offset);
        var curve = ReadSshText(blob, ref offset);
        var point = ReadSshBytes(blob, ref offset);
        if (offset != blob.Length || !StringComparer.Ordinal.Equals(algorithm, Algorithm) ||
            !StringComparer.Ordinal.Equals(curve, CurveName) || point.Length != 65 || point[0] != 0x04)
        {
            throw new DeviceIdentityStoreException("Stored OpenSSH public key is malformed.");
        }

        return (point[1..33], point[33..65]);
    }

    private static string ReadSshText(byte[] blob, ref int offset) =>
        Encoding.ASCII.GetString(ReadSshBytes(blob, ref offset));

    private static byte[] ReadSshBytes(byte[] blob, ref int offset)
    {
        if (blob.Length - offset < sizeof(uint))
            throw new DeviceIdentityStoreException("Stored OpenSSH public key is malformed.");
        var size = BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(offset, sizeof(uint)));
        offset += sizeof(uint);
        if (size > int.MaxValue || blob.Length - offset < (int)size)
            throw new DeviceIdentityStoreException("Stored OpenSSH public key is malformed.");
        var value = blob.AsSpan(offset, (int)size).ToArray();
        offset += (int)size;
        return value;
    }

    private static void WriteSshString(Stream stream, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        stream.Write(length);
        stream.Write(value);
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("DPAPI device identity storage is available only on Windows.");
    }

    private sealed record PersistedIdentity(
        int Version,
        string DeviceId,
        string DisplayName,
        string OpenSshPublicKey,
        string PublicKeyFingerprint,
        string ProtectedPrivateKeyBase64);

    private sealed class ZeroingMemoryStream(byte[] content)
        : MemoryStream(content, 0, content.Length, writable: false, publiclyVisible: false)
    {
        private byte[]? _content = content;

        protected override void Dispose(bool disposing)
        {
            if (disposing && _content is { } buffer)
            {
                CryptographicOperations.ZeroMemory(buffer);
                _content = null;
            }
            base.Dispose(disposing);
        }
    }
}

public sealed class DeviceIdentityStoreException(string message, Exception? innerException = null)
    : Exception(message, innerException);
