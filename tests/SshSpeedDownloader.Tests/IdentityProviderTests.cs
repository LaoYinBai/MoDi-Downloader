using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Tests;

public sealed class IdentityProviderTests
{
    [Fact]
    public async Task UnconfiguredCloudProviderNeverClaimsApprovalOrReturnsCredentials()
    {
        var provider = new CloudApprovedIdentityProvider();

        var result = await provider.AcquireConnectionIdentityAsync(CancellationToken.None);

        Assert.Equal(ConnectionIdentityState.NotConfigured, result.State);
        Assert.Null(result.Identity);
        Assert.Equal(IdentityProviderErrorCode.ProviderNotConfigured, result.ErrorCode);

        var device = DeviceIdentity.FromOpenSshPublicKey("Test device", "ssh-ed25519 AQID");
        var request = await provider.RequestAccessAsync(device, CancellationToken.None);
        var revoked = await provider.RevokeAuthorizationAsync(device, "credential-id", CancellationToken.None);
        Assert.False(request.IsConfigured);
        Assert.False(request.Succeeded);
        Assert.Equal(IdentityProviderErrorCode.ProviderNotConfigured, request.ErrorCode);
        Assert.False(revoked.IsConfigured);
        Assert.False(revoked.Succeeded);
    }

    [Theory]
    [InlineData(DeviceApprovalStatus.Pending, DeviceApprovalStatus.Approved, true)]
    [InlineData(DeviceApprovalStatus.Pending, DeviceApprovalStatus.Rejected, true)]
    [InlineData(DeviceApprovalStatus.Pending, DeviceApprovalStatus.Expired, true)]
    [InlineData(DeviceApprovalStatus.Pending, DeviceApprovalStatus.Revoked, true)]
    [InlineData(DeviceApprovalStatus.Approved, DeviceApprovalStatus.Revoked, true)]
    [InlineData(DeviceApprovalStatus.Rejected, DeviceApprovalStatus.Approved, false)]
    [InlineData(DeviceApprovalStatus.Expired, DeviceApprovalStatus.Approved, false)]
    [InlineData(DeviceApprovalStatus.Revoked, DeviceApprovalStatus.Approved, false)]
    public void ApprovalStateTransitionsAreExplicit(
        DeviceApprovalStatus current,
        DeviceApprovalStatus next,
        bool expected)
    {
        Assert.Equal(expected, DeviceApprovalStateMachine.TryTransition(current, next, out _));
    }

    [Fact]
    public void DeviceIdentityIdIsDerivedFromTheStableOpenSshPublicKeyFingerprint()
    {
        var first = DeviceIdentity.FromOpenSshPublicKey("MoDi Downloader Desktop", "ssh-ed25519 AQID first-comment");
        var sameKey = DeviceIdentity.FromOpenSshPublicKey("Renamed device", "ssh-ed25519 AQID another-comment");
        var otherKey = DeviceIdentity.FromOpenSshPublicKey("MoDi Downloader Desktop", "ssh-ed25519 BAUG");

        Assert.Equal("device:sha256:A5BYxvLAy0ksUzsKTRTvd8wPeKvMztUofYShogEc+4E", first.DeviceId);
        Assert.Equal("SHA256:A5BYxvLAy0ksUzsKTRTvd8wPeKvMztUofYShogEc+4E", first.PublicKeyFingerprint);
        Assert.Equal(first.DeviceId, sameKey.DeviceId);
        Assert.NotEqual(first.DeviceId, otherKey.DeviceId);
        Assert.Equal("Renamed device", sameKey.DisplayName);
    }

    [Fact]
    public void DeviceIdentityRejectsAnIdThatIsNotBoundToItsPublicKey()
    {
        Assert.Throws<ArgumentException>(() => new DeviceIdentity(
            "device:mac:00-11-22-33-44-55",
            "Test device",
            "ssh-ed25519 AQID",
            "SHA256:A5BYxvLAy0ksUzsKTRTvd8wPeKvMztUofYShogEc+4E"));
    }

    [Fact]
    public async Task CloudProviderPropagatesAuthorizationFailureWithoutInventingIdentity()
    {
        var device = DeviceIdentity.FromOpenSshPublicKey("Test device", "ssh-ed25519 AQID");
        var expected = new ConnectionIdentityResult(
            ConnectionIdentityState.Failed,
            null,
            null,
            IdentityProviderErrorCode.NetworkUnavailable,
            "authorization endpoint unavailable");
        var provider = new CloudApprovedIdentityProvider(new FailingAcquireClient(expected), device);

        var actual = await provider.AcquireConnectionIdentityAsync(CancellationToken.None);

        Assert.Equal(expected, actual);
        Assert.Null(actual.Identity);
    }

    private sealed class FailingAcquireClient(ConnectionIdentityResult result) : ICloudDeviceAuthorizationClient
    {
        public Task<IdentityProviderOperationResult<DeviceIdentity>> RegisterDeviceAsync(
            DeviceRegistrationRequest request,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<IdentityProviderOperationResult<DeviceAccessRequest>> RequestAccessAsync(
            DeviceIdentity device,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<IdentityProviderOperationResult<DeviceAccessRequest>> GetApprovalStatusAsync(
            string requestId,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<ConnectionIdentityResult> AcquireConnectionIdentityAsync(
            DeviceIdentity device,
            CancellationToken cancellationToken) => Task.FromResult(result);

        public Task<ConnectionIdentityResult> RefreshAuthorizationAsync(
            DeviceIdentity device,
            string credentialId,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<IdentityProviderOperationResult<bool>> RevokeLocalAuthorizationAsync(
            DeviceIdentity device,
            string credentialId,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
