using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Tests;

public sealed class CloudApprovedIdentityProviderTests
{
    [Fact]
    public async Task StartupWithoutSavedRequestRequiresExplicitAccessRequestAndDoesNotAcquireSsh()
    {
        var device = CreateDevice();
        var client = new FakeCloudClient();
        var provider = new CloudApprovedIdentityProvider(client, device);

        var result = await provider.AcquireConnectionIdentityAsync(CancellationToken.None);

        Assert.Equal(ConnectionIdentityState.RequestRequired, result.State);
        Assert.Null(result.Identity);
        Assert.Equal(0, client.AcquireCalls);
        Assert.Equal(0, client.RegisterCalls);
        Assert.Equal(0, client.RequestCalls);
    }

    [Fact]
    public async Task ExplicitRequestRegistersDeviceThenCreatesAccessRequest()
    {
        var device = CreateDevice();
        var client = new FakeCloudClient();
        var provider = new CloudApprovedIdentityProvider(client, device);

        var result = await provider.RequestAccessAsync(device, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal(1, client.RegisterCalls);
        Assert.Equal(1, client.RequestCalls);
        Assert.Equal("0123456789abcdef0123456789abcdef", provider.CurrentRequestId);
        Assert.Equal(0, client.AcquireCalls);
    }

    [Theory]
    [InlineData(DeviceApprovalStatus.Pending, ConnectionIdentityState.Pending, false)]
    [InlineData(DeviceApprovalStatus.Rejected, ConnectionIdentityState.Rejected, false)]
    [InlineData(DeviceApprovalStatus.Expired, ConnectionIdentityState.Expired, false)]
    [InlineData(DeviceApprovalStatus.Revoked, ConnectionIdentityState.Revoked, false)]
    [InlineData(DeviceApprovalStatus.Approved, ConnectionIdentityState.Ready, true)]
    public async Task SavedRequestStatusGatesConnectionIdentityAcquisition(
        DeviceApprovalStatus status,
        ConnectionIdentityState expected,
        bool shouldAcquire)
    {
        var device = CreateDevice();
        var client = new FakeCloudClient(status);
        var provider = new CloudApprovedIdentityProvider(client, device, "0123456789abcdef0123456789abcdef");

        var result = await provider.AcquireConnectionIdentityAsync(CancellationToken.None);

        Assert.Equal(expected, result.State);
        Assert.Equal(shouldAcquire ? 1 : 0, client.AcquireCalls);
        Assert.Equal("0123456789abcdef0123456789abcdef", client.LastStatusRequestId);
        Assert.Equal(shouldAcquire, result.Identity is not null);
    }

    [Theory]
    [InlineData(IdentityProviderErrorCode.AuthorizationRevoked, ConnectionIdentityState.Revoked)]
    [InlineData(IdentityProviderErrorCode.RequestExpired, ConnectionIdentityState.Expired)]
    [InlineData(IdentityProviderErrorCode.RequestNotFound, ConnectionIdentityState.Expired)]
    [InlineData(IdentityProviderErrorCode.DeviceNotRegistered, ConnectionIdentityState.RequestRequired)]
    public async Task AuthorizationLookupErrorsKeepDistinctTerminalStates(
        IdentityProviderErrorCode errorCode,
        ConnectionIdentityState expected)
    {
        var client = new FakeCloudClient(statusError: errorCode);
        var provider = new CloudApprovedIdentityProvider(
            client, CreateDevice(), "0123456789abcdef0123456789abcdef");

        var result = await provider.AcquireConnectionIdentityAsync(CancellationToken.None);

        Assert.Equal(expected, result.State);
        Assert.Null(result.Identity);
        Assert.Equal(errorCode, result.ErrorCode);
        Assert.Equal(0, client.AcquireCalls);
    }

    [Fact]
    public void ProviderRejectsMalformedPersistedRequestId()
    {
        Assert.Throws<ArgumentException>(() => new CloudApprovedIdentityProvider(
            new FakeCloudClient(), CreateDevice(), "request-1"));
    }

    private static DeviceIdentity CreateDevice()
    {
        var bytes = new byte[16];
        bytes[0] = 9;
        return DeviceIdentity.FromOpenSshPublicKey(
            DeviceIdFactory.Create(bytes),
            "Test device",
            "ssh-ed25519 AQID test");
    }

    private sealed class FakeCloudClient(
        DeviceApprovalStatus status = DeviceApprovalStatus.Pending,
        IdentityProviderErrorCode? statusError = null)
        : ICloudDeviceAuthorizationClient
    {
        public int RegisterCalls { get; private set; }
        public int RequestCalls { get; private set; }
        public int AcquireCalls { get; private set; }
        public string? LastStatusRequestId { get; private set; }

        public Task<IdentityProviderOperationResult<DeviceIdentity>> RegisterDeviceAsync(
            DeviceRegistrationRequest request,
            CancellationToken cancellationToken)
        {
            RegisterCalls++;
            return Task.FromResult(new IdentityProviderOperationResult<DeviceIdentity>(
                true, true, request.Device, null, null));
        }

        public Task<IdentityProviderOperationResult<DeviceAccessRequest>> RequestAccessAsync(
            DeviceIdentity device,
            CancellationToken cancellationToken)
        {
            RequestCalls++;
            return Task.FromResult(new IdentityProviderOperationResult<DeviceAccessRequest>(
                true, true, MakeRequest(status), null, null));
        }

        public Task<IdentityProviderOperationResult<DeviceAccessRequest>> GetApprovalStatusAsync(
            string requestId,
            CancellationToken cancellationToken)
        {
            LastStatusRequestId = requestId;
            if (statusError is { } error)
            {
                return Task.FromResult(new IdentityProviderOperationResult<DeviceAccessRequest>(
                    true, false, null, error, "authorization status unavailable"));
            }
            return Task.FromResult(new IdentityProviderOperationResult<DeviceAccessRequest>(
                true, true, MakeRequest(status), null, null));
        }

        public Task<ConnectionIdentityResult> AcquireConnectionIdentityAsync(
            DeviceIdentity device,
            CancellationToken cancellationToken)
        {
            AcquireCalls++;
            var server = new ServerConnectionConfiguration("relay.example", 22, "modi-download", ["SHA256:pin"]);
            var profile = new SshConnectionProfile("relay.example", 22, "modi-download", "", null)
            {
                PrivateKeyIdentityId = device.DeviceId,
                PrivateKeyStreamProvider = () => new MemoryStream([1]),
                TrustedHostFingerprints = ["SHA256:pin"]
            };
            var identity = new ConnectionIdentity(device.DeviceId, server, profile, new(true, null, false));
            return Task.FromResult(new ConnectionIdentityResult(
                ConnectionIdentityState.Ready, identity, MakeRequest(DeviceApprovalStatus.Approved), null, null));
        }

        public Task<ConnectionIdentityResult> RefreshAuthorizationAsync(
            DeviceIdentity device,
            string credentialId,
            CancellationToken cancellationToken) => AcquireConnectionIdentityAsync(device, cancellationToken);

        private static DeviceAccessRequest MakeRequest(DeviceApprovalStatus state) => new(
            "0123456789abcdef0123456789abcdef", "mdp-aaaaaaaaaaaaaaaaaaaaaaaaaa", DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch.AddDays(7), state, null, null);
    }
}
