using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Tests;

public sealed class IdentityProviderTests
{
    private const string TestPublicKey =
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBB86Yd0/1itpQGlH0UO71kgeVvGheBgm3FZDj45oqxfSoUS7vOLMBr+NSqqCnbR9Y/kl4b0yiOhkfhO9LPAavCA= vector-device";
    private const string TestFingerprint = "SHA256:QK20bOTyV10SOvM0wUUZjSG4ppE1z4tgxUMSKDf/D9A";

    [Fact]
    public async Task UnconfiguredCloudProviderNeverClaimsApprovalOrReturnsCredentials()
    {
        var provider = new CloudApprovedIdentityProvider();

        var result = await provider.AcquireConnectionIdentityAsync(CancellationToken.None);

        Assert.Equal(ConnectionIdentityState.NotConfigured, result.State);
        Assert.Null(result.Identity);
        Assert.Equal(IdentityProviderErrorCode.ProviderNotConfigured, result.ErrorCode);

        var device = DeviceIdentity.FromOpenSshPublicKey("mdp-aaaaaaaaaaaaaaaaaaaaaaaaaa", "Test device", TestPublicKey);
        var request = await provider.RequestAccessAsync(device, CancellationToken.None);
        var revoked = await provider.RevokeLocalAuthorizationAsync(CancellationToken.None);
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
    public void DeviceIdentityIdIsIndependentFromTheStableOpenSshPublicKeyFingerprint()
    {
        const string fingerprint = TestFingerprint;
        var first = new DeviceIdentity(
            "mdp-aaaaaaaaaaaaaaaaaaaaaaaaaa",
            "MoDi Downloader Desktop",
            TestPublicKey,
            fingerprint);
        var sameKey = new DeviceIdentity(
            "mdp-aaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Renamed device",
            TestPublicKey,
            fingerprint);
        var otherDevice = new DeviceIdentity(
            DeviceIdFactory.Create(Enumerable.Repeat(byte.MaxValue, 16).ToArray()),
            "MoDi Downloader Desktop",
            TestPublicKey,
            fingerprint);

        Assert.Equal("mdp-aaaaaaaaaaaaaaaaaaaaaaaaaa", first.DeviceId);
        Assert.Equal(TestFingerprint, first.PublicKeyFingerprint);
        Assert.Equal(first.DeviceId, sameKey.DeviceId);
        Assert.Equal(first.PublicKeyFingerprint, otherDevice.PublicKeyFingerprint);
        Assert.NotEqual(first.DeviceId, otherDevice.DeviceId);
        Assert.Equal("Renamed device", sameKey.DisplayName);
    }

    [Fact]
    public void DeviceIdentityRejectsAnIdThatIsNotBoundToItsPublicKey()
    {
        Assert.Throws<ArgumentException>(() => new DeviceIdentity(
            "device:mac:00-11-22-33-44-55",
            "Test device",
            TestPublicKey,
            TestFingerprint));
        var nonCanonicalId = DeviceIdFactory.Create(new byte[16])[..^1] + "b";
        Assert.Throws<ArgumentException>(() => new DeviceIdentity(
            nonCanonicalId,
            "Test device",
            TestPublicKey,
            TestFingerprint));
    }

    [Fact]
    public void DeviceIdFactoryEncodesExactly128BitsAsLowercaseUnpaddedBase32()
    {
        Assert.Equal(
            "mdp-aaaaaaaaaaaaaaaaaaaaaaaaaa",
            DeviceIdFactory.Create(new byte[16]));
        Assert.Equal(
            "mdp-77777777777777777777777774",
            DeviceIdFactory.Create(Enumerable.Repeat(byte.MaxValue, 16).ToArray()));
        Assert.Throws<ArgumentException>(() => DeviceIdFactory.Create(new byte[15]));
    }

    [Fact]
    public async Task CloudProviderPropagatesAuthorizationFailureWithoutInventingIdentity()
    {
        var device = DeviceIdentity.FromOpenSshPublicKey("mdp-aaaaaaaaaaaaaaaaaaaaaaaaaa", "Test device", TestPublicKey);
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

    [Fact]
    public async Task ExplicitRequestRegistersDeviceBeforeCreatingTheAccessRequest()
    {
        var device = DeviceIdentity.FromOpenSshPublicKey(
            "mdp-aaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test device",
            TestPublicKey);
        var client = new WorkflowClient();
        var provider = new CloudApprovedIdentityProvider(client, device);

        var result = await provider.RequestAccessAsync(CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal(DeviceApprovalStatus.Pending, result.Value?.Status);
        Assert.Equal(["register", "request"], client.Calls);
    }

    [Fact]
    public async Task LocalAuthorizationResetForgetsOnlyLocalIdentity()
    {
        var device = DeviceIdentity.FromOpenSshPublicKey(
            "mdp-aaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test device",
            TestPublicKey);
        var client = new WorkflowClient();
        var provider = new CloudApprovedIdentityProvider(client, device);

        var result = await provider.RevokeLocalAuthorizationAsync(CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.True(client.LocalIdentityForgotten);
        Assert.False(client.ServerRevoked);
    }

    private sealed class FailingAcquireClient(ConnectionIdentityResult result) : ICloudDeviceAuthorizationClient
    {
        public Task<IdentityProviderOperationResult<DeviceIdentity>> RegisterDeviceAsync(
            DeviceIdentity device,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<IdentityProviderOperationResult<DeviceAccessRequest>> RequestAccessAsync(
            DeviceIdentity device,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<IdentityProviderOperationResult<DeviceAccessRequest>> GetApprovalStatusAsync(
            string requestId,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<IdentityProviderOperationResult<DeviceAccessRequest>> GetCurrentAccessRequestAsync(
            DeviceIdentity device,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<ConnectionIdentityResult> AcquireConnectionIdentityAsync(
            DeviceIdentity device,
            CancellationToken cancellationToken) => Task.FromResult(result);

        public Task<ConnectionIdentityResult> RefreshAuthorizationAsync(
            DeviceIdentity device,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<IdentityProviderOperationResult<bool>> ForgetLocalIdentityAsync(
            DeviceIdentity device,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class WorkflowClient : ICloudDeviceAuthorizationClient
    {
        public List<string> Calls { get; } = [];
        public bool LocalIdentityForgotten { get; private set; }
        public bool ServerRevoked { get; private set; }

        public Task<IdentityProviderOperationResult<DeviceIdentity>> RegisterDeviceAsync(
            DeviceIdentity registeredDevice,
            CancellationToken cancellationToken)
        {
            Calls.Add("register");
            return Task.FromResult(new IdentityProviderOperationResult<DeviceIdentity>(
                true, true, registeredDevice, null, null));
        }

        public Task<IdentityProviderOperationResult<DeviceAccessRequest>> RequestAccessAsync(
            DeviceIdentity requestedDevice,
            CancellationToken cancellationToken)
        {
            Calls.Add("request");
            return Task.FromResult(new IdentityProviderOperationResult<DeviceAccessRequest>(
                true,
                true,
                new DeviceAccessRequest(
                    new string('c', 32),
                    requestedDevice.DeviceId,
                    DateTimeOffset.UnixEpoch,
                    DateTimeOffset.UnixEpoch.AddDays(30),
                    DeviceApprovalStatus.Pending,
                    null,
                    "Waiting for approval."),
                null,
                null));
        }

        public Task<IdentityProviderOperationResult<DeviceAccessRequest>> GetApprovalStatusAsync(
            string requestId,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<IdentityProviderOperationResult<DeviceAccessRequest>> GetCurrentAccessRequestAsync(
            DeviceIdentity currentDevice,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<ConnectionIdentityResult> AcquireConnectionIdentityAsync(
            DeviceIdentity currentDevice,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<ConnectionIdentityResult> RefreshAuthorizationAsync(
            DeviceIdentity currentDevice,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<IdentityProviderOperationResult<bool>> ForgetLocalIdentityAsync(
            DeviceIdentity currentDevice,
            CancellationToken cancellationToken)
        {
            LocalIdentityForgotten = true;
            return Task.FromResult(new IdentityProviderOperationResult<bool>(true, true, true, null, null));
        }
    }
}
