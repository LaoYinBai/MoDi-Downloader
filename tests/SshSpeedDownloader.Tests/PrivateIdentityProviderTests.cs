using System.Security.Cryptography;
using SshSpeedDownloader.Core;
using SshSpeedDownloader.Transport;
using SshSpeedDownloader.Transport.IdentityProviders;

namespace SshSpeedDownloader.Tests;

public sealed class PrivateIdentityProviderTests
{
    [Fact]
    public async Task ReportsCredentialRequiredWithoutClaimingIdentityReady()
    {
        var store = new FakePassphraseStore();
        var provider = new PrivateIdentityProvider(CreateProfile(), store, requiresPassphrase: true);

        var result = await provider.AcquireConnectionIdentityAsync(CancellationToken.None);

        Assert.Equal(ConnectionIdentityState.CredentialRequired, result.State);
        Assert.Null(result.Identity);
        Assert.Equal(IdentityProviderErrorCode.CredentialUnavailable, result.ErrorCode);
    }

    [Fact]
    public async Task ReturnsReadyIdentityAndClearsTemporaryPassphraseBuffer()
    {
        var store = new FakePassphraseStore("temporary-test-only");
        var provider = new PrivateIdentityProvider(CreateProfile(), store, requiresPassphrase: true);

        var result = await provider.AcquireConnectionIdentityAsync(CancellationToken.None);

        Assert.Equal(ConnectionIdentityState.Ready, result.State);
        Assert.NotNull(result.Identity);
        Assert.True(result.Identity.CredentialStatus.Available);
        Assert.All(store.LastReadBuffer!, value => Assert.Equal('\0', value));
    }

    [Fact]
    public async Task LocalRevocationRemovesTheSavedPassphraseAndIdentityIsNoLongerReady()
    {
        var store = new FakePassphraseStore("temporary-test-only");
        var provider = new PrivateIdentityProvider(CreateProfile(), store, requiresPassphrase: true);

        provider.ForgetPassphrase();
        var afterRevoke = await provider.AcquireConnectionIdentityAsync(CancellationToken.None);

        Assert.Equal(ConnectionIdentityState.CredentialRequired, afterRevoke.State);
        Assert.False(store.ContainsCredential);
    }

    [Fact]
    public void ProviderFactorySelectsTheConfiguredIdentitySource()
    {
        var store = new FakePassphraseStore();

        var cloud = ConnectionIdentityProviderFactory.Create(
            ConnectionIdentityProviderKind.CloudApproved,
            CreateProfile(),
            store);

        Assert.Equal(ConnectionIdentityProviderKind.CloudApproved, cloud.Kind);
    }

    private static SshConnectionProfile CreateProfile() => new(
        "example.test",
        22,
        "download",
        "",
        null)
    {
        PrivateKeyIdentityId = "test-identity",
        PrivateKeyStreamProvider = () => new MemoryStream([1, 2, 3]),
        TrustedHostFingerprints = ["SHA256:test-pin"]
    };

    private sealed class FakePassphraseStore(string? passphrase = null) : IPrivatePassphraseStore
    {
        private char[]? _secret = passphrase?.ToCharArray();
        public char[]? LastReadBuffer { get; private set; }
        public bool ContainsCredential => _secret is not null;

        public char[]? TryReadPassphrase(string targetName)
        {
            LastReadBuffer = _secret?.ToArray();
            return LastReadBuffer;
        }

        public void SavePassphrase(string targetName, ReadOnlySpan<char> passphrase) =>
            _secret = passphrase.ToArray();

        public void ForgetPassphrase(string targetName)
        {
            if (_secret is not null)
                Array.Clear(_secret);
            _secret = null;
        }
    }
}
