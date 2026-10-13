using System.Security.Cryptography;
using System.Globalization;
using System.Text;

namespace SshSpeedDownloader.Core;

public enum ConnectionIdentityProviderKind
{
    PrivateIdentity,
    CloudApproved
}

public enum ConnectionIdentityState
{
    Ready,
    CredentialRequired,
    Pending,
    Rejected,
    Expired,
    Revoked,
    NotConfigured,
    Failed
}

public enum DeviceApprovalStatus
{
    Pending,
    Approved,
    Rejected,
    Expired,
    Revoked
}

public enum IdentityProviderErrorCode
{
    ProviderNotConfigured,
    DeviceNotRegistered,
    ApprovalPending,
    AccessRejected,
    RequestExpired,
    AuthorizationRevoked,
    CredentialUnavailable,
    AuthenticationFailed,
    NetworkUnavailable,
    Unknown
}

public static class DeviceIdFactory
{
    private const string Alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    private const int RandomByteCount = 16;

    public static string Create(ReadOnlySpan<byte> randomBytes)
    {
        if (randomBytes.Length != RandomByteCount)
            throw new ArgumentException("Device IDs require exactly 16 random bytes.", nameof(randomBytes));

        var encoded = new char[26];
        for (var outputIndex = 0; outputIndex < encoded.Length; outputIndex++)
        {
            var value = 0;
            for (var bit = 0; bit < 5; bit++)
            {
                var sourceBit = outputIndex * 5 + bit;
                value <<= 1;
                if (sourceBit < 128)
                    value |= (randomBytes[sourceBit / 8] >> (7 - sourceBit % 8)) & 1;
            }
            encoded[outputIndex] = Alphabet[value];
        }

        return $"mdp-{new string(encoded)}";
    }

    public static bool IsValid(string? deviceId)
    {
        if (deviceId is null || deviceId.Length != 30 ||
            !deviceId.StartsWith("mdp-", StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var character in deviceId.AsSpan(4))
        {
            if (Alphabet.IndexOf(character) < 0) return false;
        }

        return (Alphabet.IndexOf(deviceId[^1]) & 0b11) == 0;
    }
}

public sealed record DeviceIdentity
{
    public DeviceIdentity(string deviceId, string displayName, string publicKey, string publicKeyFingerprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        if (!DeviceIdFactory.IsValid(deviceId))
            throw new ArgumentException("Device ID must use the mdp- format.", nameof(deviceId));
        var derivedFingerprint = DeriveFingerprint(publicKey);
        if (!StringComparer.Ordinal.Equals(publicKeyFingerprint, derivedFingerprint))
            throw new ArgumentException("Public-key fingerprint does not match the supplied OpenSSH key.", nameof(publicKeyFingerprint));

        DeviceId = deviceId;
        DisplayName = displayName;
        PublicKey = publicKey.Trim();
        PublicKeyFingerprint = publicKeyFingerprint;
    }

    public string DeviceId { get; }
    public string DisplayName { get; }
    public string PublicKey { get; }
    public string PublicKeyFingerprint { get; }

    public static DeviceIdentity FromOpenSshPublicKey(string deviceId, string displayName, string publicKey)
    {
        if (!DeviceIdFactory.IsValid(deviceId))
            throw new ArgumentException("Device ID must use the mdp- format.", nameof(deviceId));
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        return new DeviceIdentity(deviceId, displayName, publicKey, DeriveFingerprint(publicKey));
    }

    private static string DeriveFingerprint(string publicKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(publicKey);
        var fields = publicKey.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 2)
            throw new ArgumentException("An OpenSSH public key is required.", nameof(publicKey));

        byte[] keyBlob;
        try
        {
            keyBlob = Convert.FromBase64String(fields[1]);
            if (!StringComparer.Ordinal.Equals(Convert.ToBase64String(keyBlob), fields[1]))
                throw new FormatException();
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("The OpenSSH public key is malformed.", nameof(publicKey), exception);
        }

        if (keyBlob.Length == 0)
            throw new ArgumentException("The OpenSSH public key is malformed.", nameof(publicKey));

        var fingerprintBody = Convert.ToBase64String(SHA256.HashData(keyBlob)).TrimEnd('=');
        return $"SHA256:{fingerprintBody}";
    }
}

public sealed record SignedRequestEnvelope(
    string KeyId,
    string ChallengeId,
    string Nonce,
    long UnixTimestamp,
    string SignatureBase64);

public static class DeviceRequestSigner
{
    public const string Domain = "MODI-AUTH-DEVICE-V1";
    private const string P256Oid = "1.2.840.10045.3.1.7";

    public static SignedRequestEnvelope Sign(
        ECDsa privateKey,
        string keyId,
        string challengeId,
        string nonce,
        long unixTimestamp,
        string method,
        string requestTarget,
        ReadOnlySpan<byte> rawBody)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ValidateToken(keyId, nameof(keyId));
        ValidateToken(challengeId, nameof(challengeId));
        ValidateToken(nonce, nameof(nonce));
        if (privateKey.KeySize != 256 ||
            !StringComparer.Ordinal.Equals(privateKey.ExportParameters(includePrivateParameters: false).Curve.Oid.Value, P256Oid))
        {
            throw new ArgumentException("Device request signatures require an ECDSA P-256 key.", nameof(privateKey));
        }

        var canonical = BuildCanonicalPayload(method, requestTarget, rawBody, nonce, unixTimestamp);
        try
        {
            var signature = privateKey.SignData(
                canonical,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
            return new SignedRequestEnvelope(
                keyId,
                challengeId,
                nonce,
                unixTimestamp,
                Convert.ToBase64String(signature));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    public static byte[] BuildCanonicalPayload(
        string method,
        string requestTarget,
        ReadOnlySpan<byte> rawBody,
        string nonce,
        long unixTimestamp)
    {
        ValidateToken(nonce, nameof(nonce));
        if (!TryNormalizeMethod(method, out var normalizedMethod))
            throw new ArgumentException("HTTP method is invalid.", nameof(method));
        if (!TryNormalizeRequestTarget(requestTarget, out var normalizedTarget))
            throw new ArgumentException("HTTP request target is invalid.", nameof(requestTarget));

        var bodyHash = Convert.ToHexString(SHA256.HashData(rawBody)).ToLowerInvariant();
        var canonical = string.Join('\n',
            Domain,
            normalizedMethod,
            normalizedTarget,
            bodyHash,
            nonce,
            unixTimestamp.ToString(CultureInfo.InvariantCulture));
        return Encoding.UTF8.GetBytes(canonical);
    }

    private static void ValidateToken(string? value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128 ||
            value.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_'))
        {
            throw new ArgumentException("Signed request token is invalid.", parameterName);
        }
    }

    private static bool TryNormalizeMethod(string? method, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(method) || method.Length > 16 ||
            method.Any(character => !char.IsAsciiLetter(character)))
        {
            return false;
        }

        normalized = method.ToUpperInvariant();
        return true;
    }

    private static bool TryNormalizeRequestTarget(string? requestTarget, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(requestTarget) || requestTarget[0] != '/' ||
            requestTarget.StartsWith("//", StringComparison.Ordinal) || requestTarget.Contains('#') ||
            requestTarget.Any(character => char.IsControl(character) || char.IsWhiteSpace(character) || character > 0x7f))
        {
            return false;
        }

        var queryIndex = requestTarget.IndexOf('?');
        var path = queryIndex < 0 ? requestTarget : requestTarget[..queryIndex];
        if (!TryNormalizeEscapes(path, rejectEncodedPathSeparators: true, out path) ||
            path.Split('/').Any(IsDotSegment))
        {
            return false;
        }

        if (queryIndex < 0)
        {
            normalized = path;
            return true;
        }

        var query = requestTarget[(queryIndex + 1)..];
        if (query.Length == 0)
        {
            normalized = path + "?";
            return true;
        }

        var parts = query.Split('&', StringSplitOptions.None);
        if (parts.Any(string.IsNullOrEmpty)) return false;
        var normalizedParts = new List<string>(parts.Length);
        foreach (var part in parts)
        {
            if (!TryNormalizeEscapes(part, rejectEncodedPathSeparators: false, out var normalizedPart))
                return false;
            normalizedParts.Add(normalizedPart);
        }

        normalizedParts.Sort(StringComparer.Ordinal);
        normalized = path + "?" + string.Join('&', normalizedParts);
        return true;
    }

    private static bool TryNormalizeEscapes(string value, bool rejectEncodedPathSeparators, out string normalized)
    {
        var builder = new StringBuilder(value.Length);
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (character != '%')
            {
                if (!IsAllowedUriCharacter(character))
                {
                    normalized = string.Empty;
                    return false;
                }
                builder.Append(character);
                continue;
            }

            if (index + 2 >= value.Length || !byte.TryParse(
                    value.AsSpan(index + 1, 2),
                    NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture,
                    out var decoded))
            {
                normalized = string.Empty;
                return false;
            }

            if (rejectEncodedPathSeparators && decoded is 0x2f or 0x5c)
            {
                normalized = string.Empty;
                return false;
            }

            builder.Append('%').Append(decoded.ToString("X2", CultureInfo.InvariantCulture));
            index += 2;
        }

        normalized = builder.ToString();
        return true;
    }

    private static bool IsAllowedUriCharacter(char character) =>
        char.IsAsciiLetterOrDigit(character) || character is '/' or '-' or '.' or '_' or '~' or '!' or '$' or '&' or '\'' or '(' or ')' or '*' or '+' or ',' or ';' or '=' or ':' or '@' or '?';

    private static bool IsDotSegment(string segment)
    {
        try
        {
            return Uri.UnescapeDataString(segment) is "." or "..";
        }
        catch (UriFormatException)
        {
            return true;
        }
    }
}

public interface IDeviceIdentityStore
{
    Task<LocalDeviceIdentity> LoadOrCreateAsync(CancellationToken cancellationToken);

    Task<bool> ForgetLocalIdentityAsync(CancellationToken cancellationToken);
}

public sealed class LocalDeviceIdentity
{
    private readonly Func<Stream> _openPrivateKeyStream;

    public LocalDeviceIdentity(DeviceIdentity deviceIdentity, Func<Stream> openPrivateKeyStream)
    {
        ArgumentNullException.ThrowIfNull(deviceIdentity);
        ArgumentNullException.ThrowIfNull(openPrivateKeyStream);
        DeviceIdentity = deviceIdentity;
        _openPrivateKeyStream = openPrivateKeyStream;
    }

    public DeviceIdentity DeviceIdentity { get; }

    public string DeviceKeyId => DeviceIdentity.DeviceId;

    public Stream OpenPrivateKeyStream() => _openPrivateKeyStream();
}

public sealed record DeviceRegistrationRequest(
    DeviceIdentity Device,
    DateTimeOffset CreatedUtc,
    string ProofOfPossession);

public sealed record DeviceAccessRequest(
    string RequestId,
    string DeviceId,
    DateTimeOffset CreatedUtc,
    DateTimeOffset ExpiresUtc,
    DeviceApprovalStatus Status,
    IdentityProviderErrorCode? ErrorCode,
    string? UserMessage);

public sealed record ServerConnectionConfiguration(
    string Host,
    int Port,
    string Username,
    IReadOnlyList<string> TrustedHostFingerprints);

public sealed record ConnectionCredentialStatus(
    bool Available,
    DateTimeOffset? ExpiresUtc,
    bool Revoked,
    string? CredentialId = null);

public sealed record ConnectionIdentity(
    string IdentityId,
    ServerConnectionConfiguration Server,
    SshConnectionProfile SshProfile,
    ConnectionCredentialStatus CredentialStatus);

public sealed record ConnectionIdentityResult(
    ConnectionIdentityState State,
    ConnectionIdentity? Identity,
    DeviceAccessRequest? AccessRequest,
    IdentityProviderErrorCode? ErrorCode,
    string? UserMessage);

public sealed record IdentityProviderOperationResult<T>(
    bool IsConfigured,
    bool Succeeded,
    T? Value,
    IdentityProviderErrorCode? ErrorCode,
    string? UserMessage);

public interface IConnectionIdentityProvider
{
    ConnectionIdentityProviderKind Kind { get; }

    ValueTask<ConnectionIdentityResult> AcquireConnectionIdentityAsync(CancellationToken cancellationToken);

    ValueTask<IdentityProviderOperationResult<bool>> RevokeLocalAuthorizationAsync(CancellationToken cancellationToken);
}

public interface ICloudDeviceAuthorizationClient
{
    Task<IdentityProviderOperationResult<DeviceIdentity>> RegisterDeviceAsync(
        DeviceRegistrationRequest request,
        CancellationToken cancellationToken);

    Task<IdentityProviderOperationResult<DeviceAccessRequest>> RequestAccessAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken);

    Task<IdentityProviderOperationResult<DeviceAccessRequest>> GetApprovalStatusAsync(
        string requestId,
        CancellationToken cancellationToken);

    Task<ConnectionIdentityResult> AcquireConnectionIdentityAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken);

    Task<ConnectionIdentityResult> RefreshAuthorizationAsync(
        DeviceIdentity device,
        string credentialId,
        CancellationToken cancellationToken);

    Task<IdentityProviderOperationResult<bool>> RevokeLocalAuthorizationAsync(
        DeviceIdentity device,
        string credentialId,
        CancellationToken cancellationToken);
}

public sealed class CloudApprovedIdentityProvider : IConnectionIdentityProvider
{
    private readonly ICloudDeviceAuthorizationClient? _client;
    private readonly DeviceIdentity? _device;

    public CloudApprovedIdentityProvider(
        ICloudDeviceAuthorizationClient? client = null,
        DeviceIdentity? device = null)
    {
        _client = client;
        _device = device;
    }

    public ConnectionIdentityProviderKind Kind => ConnectionIdentityProviderKind.CloudApproved;

    public async ValueTask<ConnectionIdentityResult> AcquireConnectionIdentityAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_client is null || _device is null)
            return NotConfiguredIdentity();
        return await _client.AcquireConnectionIdentityAsync(_device, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<IdentityProviderOperationResult<bool>> RevokeLocalAuthorizationAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_client is null || _device is null)
            return NotConfiguredOperation<bool>("云端设备鉴权服务尚未配置。");

        var status = await AcquireConnectionIdentityAsync(cancellationToken).ConfigureAwait(false);
        if (status.Identity is null)
            return new IdentityProviderOperationResult<bool>(
                status.State != ConnectionIdentityState.NotConfigured,
                false,
                false,
                status.ErrorCode,
                status.UserMessage);
        var credentialId = status.Identity.CredentialStatus.CredentialId;
        if (string.IsNullOrWhiteSpace(credentialId))
            return new IdentityProviderOperationResult<bool>(
                true,
                false,
                false,
                IdentityProviderErrorCode.CredentialUnavailable,
                "授权提供者没有返回可撤销凭据 ID。 ");
        return await _client.RevokeLocalAuthorizationAsync(
            _device,
            credentialId,
            cancellationToken).ConfigureAwait(false);
    }

    public Task<IdentityProviderOperationResult<DeviceIdentity>> RegisterDeviceAsync(
        DeviceRegistrationRequest request,
        CancellationToken cancellationToken) =>
        _client is null
            ? Task.FromResult(new IdentityProviderOperationResult<DeviceIdentity>(
                false,
                false,
                null,
                IdentityProviderErrorCode.ProviderNotConfigured,
                "云端设备鉴权服务尚未配置。"))
            : _client.RegisterDeviceAsync(request, cancellationToken);

    public Task<IdentityProviderOperationResult<DeviceAccessRequest>> RequestAccessAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken) =>
        _client?.RequestAccessAsync(device, cancellationToken)
        ?? Task.FromResult(NotConfiguredOperation<DeviceAccessRequest>("云端设备鉴权服务尚未配置。"));

    public Task<IdentityProviderOperationResult<DeviceAccessRequest>> GetApprovalStatusAsync(
        string requestId,
        CancellationToken cancellationToken) =>
        _client?.GetApprovalStatusAsync(requestId, cancellationToken)
        ?? Task.FromResult(NotConfiguredOperation<DeviceAccessRequest>("云端设备鉴权服务尚未配置。"));

    public Task<ConnectionIdentityResult> RefreshAuthorizationAsync(
        DeviceIdentity device,
        string credentialId,
        CancellationToken cancellationToken) =>
        _client?.RefreshAuthorizationAsync(device, credentialId, cancellationToken)
        ?? Task.FromResult(NotConfiguredIdentity());

    public Task<IdentityProviderOperationResult<bool>> RevokeAuthorizationAsync(
        DeviceIdentity device,
        string credentialId,
        CancellationToken cancellationToken) =>
        _client?.RevokeLocalAuthorizationAsync(device, credentialId, cancellationToken)
        ?? Task.FromResult(NotConfiguredOperation<bool>("云端设备鉴权服务尚未配置。"));

    private static ConnectionIdentityResult NotConfiguredIdentity() => new(
        ConnectionIdentityState.NotConfigured,
        null,
        null,
        IdentityProviderErrorCode.ProviderNotConfigured,
        "云端设备鉴权服务尚未配置；未创建或伪造任何授权凭证。");

    private static IdentityProviderOperationResult<T> NotConfiguredOperation<T>(string message) => new(
        false,
        false,
        default,
        IdentityProviderErrorCode.ProviderNotConfigured,
        message);
}

public static class DeviceApprovalStateMachine
{
    public static bool TryTransition(
        DeviceApprovalStatus current,
        DeviceApprovalStatus next,
        out DeviceApprovalStatus result)
    {
        var allowed = current switch
        {
            DeviceApprovalStatus.Pending => next is DeviceApprovalStatus.Approved or
                DeviceApprovalStatus.Rejected or DeviceApprovalStatus.Expired or DeviceApprovalStatus.Revoked,
            DeviceApprovalStatus.Approved => next == DeviceApprovalStatus.Revoked,
            _ => false
        };
        result = allowed ? next : current;
        return allowed;
    }
}
