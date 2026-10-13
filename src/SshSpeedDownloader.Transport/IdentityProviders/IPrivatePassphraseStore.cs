using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Transport.IdentityProviders;

public interface IPrivatePassphraseStore
{
    char[]? TryReadPassphrase(string targetName);
    void SavePassphrase(string targetName, ReadOnlySpan<char> passphrase);
    void ForgetPassphrase(string targetName);
}

public interface IPrivateIdentityProvisioner
{
    void StorePassphrase(ReadOnlySpan<char> passphrase);
    void ForgetPassphrase();
}

public static class ConnectionIdentityProviderFactory
{
    public static IConnectionIdentityProvider Create(
        ConnectionIdentityProviderKind kind,
        SshConnectionProfile? privateProfile,
        IPrivatePassphraseStore privatePassphrases,
        ICloudDeviceAuthorizationClient? cloudClient = null,
        DeviceIdentity? device = null)
    {
        ArgumentNullException.ThrowIfNull(privatePassphrases);
        return kind switch
        {
            ConnectionIdentityProviderKind.PrivateIdentity =>
                new PrivateIdentityProvider(privateProfile, privatePassphrases, requiresPassphrase: true),
            ConnectionIdentityProviderKind.CloudApproved =>
                new CloudApprovedIdentityProvider(cloudClient, device),
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };
    }
}

public sealed class PrivateIdentityProvider : IConnectionIdentityProvider, IPrivateIdentityProvisioner
{
    private readonly SshConnectionProfile? _profile;
    private readonly IPrivatePassphraseStore _passphrases;
    private readonly bool _requiresPassphrase;

    public PrivateIdentityProvider(
        SshConnectionProfile? profile,
        IPrivatePassphraseStore passphrases,
        bool requiresPassphrase)
    {
        ArgumentNullException.ThrowIfNull(passphrases);
        _profile = profile;
        _passphrases = passphrases;
        _requiresPassphrase = requiresPassphrase;
    }

    public ConnectionIdentityProviderKind Kind => ConnectionIdentityProviderKind.PrivateIdentity;

    public ValueTask<ConnectionIdentityResult> AcquireConnectionIdentityAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_profile is null || !SshConnectionProfileValidator.TryValidate(_profile, out _))
            return ValueTask.FromResult(new ConnectionIdentityResult(
                ConnectionIdentityState.NotConfigured,
                null,
                null,
                IdentityProviderErrorCode.ProviderNotConfigured,
                "私人版 SSH 身份未配置。"));

        var targetName = WindowsCredentialVault.GetTargetName(_profile);
        var secret = _passphrases.TryReadPassphrase(targetName);
        var hasSecret = secret is { Length: > 0 };
        if (secret is not null)
            Array.Clear(secret);

        if (_requiresPassphrase && !hasSecret)
            return ValueTask.FromResult(new ConnectionIdentityResult(
                ConnectionIdentityState.CredentialRequired,
                null,
                null,
                IdentityProviderErrorCode.CredentialUnavailable,
                "需要首次解锁私钥；口令只保存到 Windows 凭据管理器。"));

        var server = new ServerConnectionConfiguration(
            _profile.Host,
            _profile.Port,
            _profile.Username,
            _profile.TrustedHostFingerprints.Count > 0
                ? _profile.TrustedHostFingerprints
                : string.IsNullOrWhiteSpace(_profile.TrustedHostFingerprint)
                    ? Array.Empty<string>()
                    : [_profile.TrustedHostFingerprint]);
        var identity = new ConnectionIdentity(
            _profile.PrivateKeyIdentityId ?? Path.GetFullPath(_profile.PrivateKeyPath),
            server,
            _profile,
            new ConnectionCredentialStatus(hasSecret, null, false));
        return ValueTask.FromResult(new ConnectionIdentityResult(
            ConnectionIdentityState.Ready,
            identity,
            null,
            null,
            null));
    }

    public void StorePassphrase(ReadOnlySpan<char> passphrase)
    {
        if (_profile is null)
            throw new InvalidOperationException("私人身份未配置。 ");
        _passphrases.SavePassphrase(WindowsCredentialVault.GetTargetName(_profile), passphrase);
    }

    public void ForgetPassphrase()
    {
        if (_profile is not null)
            _passphrases.ForgetPassphrase(WindowsCredentialVault.GetTargetName(_profile));
    }
}
