using System.Security.Cryptography;

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

public sealed record DeviceIdentity
{
    public DeviceIdentity(string deviceId, string displayName, string publicKey, string publicKeyFingerprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        if (!DeviceIdFactory.IsValid(deviceId))
            throw new ArgumentException("Device ID must be a valid mdp- identity.", nameof(deviceId));
        var fingerprint = DeriveFingerprint(publicKey);
        if (!StringComparer.Ordinal.Equals(publicKeyFingerprint, fingerprint))
            throw new ArgumentException("The public-key fingerprint does not match the supplied OpenSSH public key.", nameof(publicKeyFingerprint));

        DeviceId = deviceId;
        DisplayName = displayName;
        PublicKey = publicKey.Trim();
        PublicKeyFingerprint = fingerprint;
    }

    public string DeviceId { get; }
    public string DisplayName { get; }
    public string PublicKey { get; }
    public string PublicKeyFingerprint { get; }

    public static DeviceIdentity FromOpenSshPublicKey(string deviceId, string displayName, string publicKey)
    {
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

public static class DeviceIdFactory
{
    private const string Alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    private const int RandomByteCount = 16;
    private const string Prefix = "mdp-";

    public static string Create()
    {
        var randomBytes = RandomNumberGenerator.GetBytes(RandomByteCount);
        try
        {
            return Create(randomBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(randomBytes);
        }
    }

    public static string Create(ReadOnlySpan<byte> randomBytes)
    {
        if (randomBytes.Length != RandomByteCount)
            throw new ArgumentException("Device IDs require exactly 128 bits of entropy.", nameof(randomBytes));

        Span<char> encoded = stackalloc char[26];
        uint buffer = 0;
        var bitCount = 0;
        var outputIndex = 0;
        foreach (var value in randomBytes)
        {
            buffer = (buffer << 8) | value;
            bitCount += 8;
            while (bitCount >= 5)
            {
                bitCount -= 5;
                encoded[outputIndex++] = Alphabet[(int)((buffer >> bitCount) & 31)];
                buffer &= bitCount == 0 ? 0u : (1u << bitCount) - 1;
            }
        }

        if (bitCount > 0)
            encoded[outputIndex++] = Alphabet[(int)((buffer << (5 - bitCount)) & 31)];
        if (outputIndex != encoded.Length)
            throw new InvalidOperationException("Device ID encoding produced an invalid length.");

        return Prefix + new string(encoded);
    }

    public static bool IsValid(string? deviceId)
    {
        if (deviceId is not { Length: 30 } ||
            !deviceId.StartsWith(Prefix, StringComparison.Ordinal) ||
            deviceId.AsSpan(Prefix.Length).IndexOfAnyExcept(Alphabet) >= 0)
            return false;

        return (Alphabet.IndexOf(deviceId[^1]) & 0b11) == 0;
    }
}

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

public interface ICloudAuthorizationWorkflow
{
    string DeviceId { get; }
    string DeviceDisplayName { get; }

    Task<IdentityProviderOperationResult<DeviceAccessRequest>> RequestAccessAsync(
        CancellationToken cancellationToken);

    Task<IdentityProviderOperationResult<DeviceAccessRequest>> RefreshAccessStatusAsync(
        CancellationToken cancellationToken);
}

public interface ICloudDeviceAuthorizationClient
{
    Task<IdentityProviderOperationResult<DeviceIdentity>> RegisterDeviceAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken);

    Task<IdentityProviderOperationResult<DeviceAccessRequest>> RequestAccessAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken);

    Task<IdentityProviderOperationResult<DeviceAccessRequest>> GetApprovalStatusAsync(
        string requestId,
        CancellationToken cancellationToken);

    Task<IdentityProviderOperationResult<DeviceAccessRequest>> GetCurrentAccessRequestAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken);

    Task<ConnectionIdentityResult> AcquireConnectionIdentityAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken);

    Task<ConnectionIdentityResult> RefreshAuthorizationAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken);

    Task<IdentityProviderOperationResult<bool>> ForgetLocalIdentityAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken);
}

public sealed class CloudApprovedIdentityProvider : IConnectionIdentityProvider, ICloudAuthorizationWorkflow
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
    public string DeviceId => _device?.DeviceId ?? "";
    public string DeviceDisplayName => _device?.DisplayName ?? "";

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

        return await _client.ForgetLocalIdentityAsync(
            _device,
            cancellationToken).ConfigureAwait(false);
    }

    public Task<IdentityProviderOperationResult<DeviceIdentity>> RegisterDeviceAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken) =>
        _client is null
            ? Task.FromResult(new IdentityProviderOperationResult<DeviceIdentity>(
                false,
                false,
                null,
                IdentityProviderErrorCode.ProviderNotConfigured,
                "云端设备鉴权服务尚未配置。"))
            : _client.RegisterDeviceAsync(device, cancellationToken);

    public async Task<IdentityProviderOperationResult<DeviceAccessRequest>> RequestAccessAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_client is null || _device is null)
            return NotConfiguredOperation<DeviceAccessRequest>("云端设备鉴权服务尚未配置。");

        var registration = await _client.RegisterDeviceAsync(_device, cancellationToken).ConfigureAwait(false);
        if (!registration.Succeeded)
            return new IdentityProviderOperationResult<DeviceAccessRequest>(
                registration.IsConfigured,
                false,
                null,
                registration.ErrorCode,
                registration.UserMessage);
        return await _client.RequestAccessAsync(_device, cancellationToken).ConfigureAwait(false);
    }

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

    public Task<IdentityProviderOperationResult<DeviceAccessRequest>> RefreshAccessStatusAsync(
        CancellationToken cancellationToken) =>
        _device is null
            ? Task.FromResult(NotConfiguredOperation<DeviceAccessRequest>("本机设备身份尚未配置。"))
            : _client?.GetCurrentAccessRequestAsync(_device, cancellationToken)
            ?? Task.FromResult(NotConfiguredOperation<DeviceAccessRequest>("云端设备鉴权服务尚未配置。"));

    public Task<ConnectionIdentityResult> RefreshAuthorizationAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken) =>
        _client?.RefreshAuthorizationAsync(device, cancellationToken)
        ?? Task.FromResult(NotConfiguredIdentity());

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
