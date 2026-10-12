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
        var derived = DeriveIdentity(publicKey);
        if (!StringComparer.Ordinal.Equals(deviceId, derived.DeviceId) ||
            !StringComparer.Ordinal.Equals(publicKeyFingerprint, derived.Fingerprint))
            throw new ArgumentException("Device ID and fingerprint must match the supplied OpenSSH public key.", nameof(deviceId));

        DeviceId = deviceId;
        DisplayName = displayName;
        PublicKey = publicKey.Trim();
        PublicKeyFingerprint = publicKeyFingerprint;
    }

    public string DeviceId { get; }
    public string DisplayName { get; }
    public string PublicKey { get; }
    public string PublicKeyFingerprint { get; }

    public static DeviceIdentity FromOpenSshPublicKey(string displayName, string publicKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        var derived = DeriveIdentity(publicKey);
        return new DeviceIdentity(derived.DeviceId, displayName, publicKey, derived.Fingerprint);
    }

    private static (string DeviceId, string Fingerprint) DeriveIdentity(string publicKey)
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
        return ($"device:sha256:{fingerprintBody}", $"SHA256:{fingerprintBody}");
    }
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
