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

        var device = CreateTestDevice("Test device", 1);
        var request = await provider.RequestAccessAsync(device, CancellationToken.None);
        Assert.False(request.IsConfigured);
        Assert.False(request.Succeeded);
        Assert.Equal(IdentityProviderErrorCode.ProviderNotConfigured, request.ErrorCode);
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
    public void DeviceIdentityUsesAnInstallationIdIndependentFromThePublicKeyFingerprint()
    {
        var first = CreateTestDevice("MoDi Downloader Desktop", 1);
        var sameKeyDifferentInstall = DeviceIdentity.FromOpenSshPublicKey(
            TestDeviceId(2), "Renamed device", "ssh-ed25519 AQID another-comment");
        var otherKey = DeviceIdentity.FromOpenSshPublicKey(
            TestDeviceId(3), "MoDi Downloader Desktop", "ssh-ed25519 BAUG");

        Assert.StartsWith("mdp-", first.DeviceId, StringComparison.Ordinal);
        Assert.Equal(30, first.DeviceId.Length);
        Assert.Equal("SHA256:A5BYxvLAy0ksUzsKTRTvd8wPeKvMztUofYShogEc+4E", first.PublicKeyFingerprint);
        Assert.NotEqual(first.DeviceId, sameKeyDifferentInstall.DeviceId);
        Assert.Equal(first.PublicKeyFingerprint, sameKeyDifferentInstall.PublicKeyFingerprint);
        Assert.NotEqual(first.DeviceId, otherKey.DeviceId);
        Assert.Equal("Renamed device", sameKeyDifferentInstall.DisplayName);
    }

    [Fact]
    public void DeviceIdentityRejectsLegacyOrMalformedDeviceIdentifiers()
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
        var device = CreateTestDevice("Test device", 4);
        var expected = new ConnectionIdentityResult(
            ConnectionIdentityState.Failed,
            null,
            null,
            IdentityProviderErrorCode.NetworkUnavailable,
            "authorization endpoint unavailable");
        var provider = new CloudApprovedIdentityProvider(
            new FailingAcquireClient(expected), device, "0123456789abcdef0123456789abcdef");

        var actual = await provider.AcquireConnectionIdentityAsync(CancellationToken.None);

        Assert.Equal(expected.State, actual.State);
        Assert.Equal(expected.ErrorCode, actual.ErrorCode);
        Assert.Equal(expected.UserMessage, actual.UserMessage);
        Assert.Null(actual.Identity);
        Assert.Equal(DeviceApprovalStatus.Approved, actual.AccessRequest?.Status);
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
            CancellationToken cancellationToken) => Task.FromResult(new IdentityProviderOperationResult<DeviceAccessRequest>(
                true,
                true,
                new DeviceAccessRequest(
                    requestId, "mdp-aaaaaaaaaaaaaaaaaaaaaaaaaa", DateTimeOffset.UnixEpoch,
                    DateTimeOffset.UnixEpoch.AddDays(7), DeviceApprovalStatus.Approved, null, null),
                null,
                null));

        public Task<ConnectionIdentityResult> AcquireConnectionIdentityAsync(
            DeviceIdentity device,
            CancellationToken cancellationToken) => Task.FromResult(result);

        public Task<ConnectionIdentityResult> RefreshAuthorizationAsync(
            DeviceIdentity device,
            string credentialId,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private static DeviceIdentity CreateTestDevice(string displayName, byte seed) =>
        DeviceIdentity.FromOpenSshPublicKey(TestDeviceId(seed), displayName, "ssh-ed25519 AQID");

    private static string TestDeviceId(byte seed)
    {
        var bytes = new byte[16];
        bytes[0] = seed;
        return DeviceIdFactory.Create(bytes);
    }
}
