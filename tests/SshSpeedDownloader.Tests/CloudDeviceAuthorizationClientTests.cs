using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SshSpeedDownloader.Core;
using SshSpeedDownloader.Transport.IdentityProviders;

namespace SshSpeedDownloader.Tests;

public sealed class CloudDeviceAuthorizationClientTests
{
    [Fact]
    public async Task RegistrationUsesFreshDeviceChallengeAndProvesPossessionInSignedRequest()
    {
        using var material = TestIdentity.Create();
        var handler = new QueueHttpHandler(
            _ => Json(HttpStatusCode.OK, $"{{\"challengeId\":\"challenge-1\",\"nonce\":\"nonce-1\",\"expiresUtc\":\"{DateTimeOffset.UtcNow.AddMinutes(4):O}\"}}"),
            _ => Json(HttpStatusCode.Created, $"{{\"deviceId\":\"{material.Device.DeviceId}\",\"displayName\":\"Test device\",\"openSshPublicKey\":\"{material.Device.PublicKey}\",\"publicKeyFingerprint\":\"{material.Device.PublicKeyFingerprint}\",\"createdUtc\":\"{DateTimeOffset.UtcNow:O}\",\"status\":\"registered\"}}"));
        using var httpClient = new HttpClient(handler);
        var client = new CloudDeviceAuthorizationClient(ValidOptions, new FakeIdentityStore(material.Identity), httpClient);

        var result = await client.RegisterDeviceAsync(new DeviceRegistrationRequest(material.Device), CancellationToken.None);

        Assert.True(result.IsConfigured);
        Assert.True(result.Succeeded, $"{result.ErrorCode}: {result.UserMessage}; requests={string.Join(',', handler.Captured.Select(item => item.PathAndQuery))}");
        Assert.Equal(material.Device, result.Value);
        Assert.Equal(2, handler.Captured.Count);
        Assert.Equal("POST", handler.Captured[0].Method);
        Assert.Equal("/v1/device-challenges", handler.Captured[0].PathAndQuery);
        Assert.DoesNotContain("X-MoDi-Key-Id", handler.Captured[0].Headers.Keys);
        Assert.Equal("POST", handler.Captured[1].Method);
        Assert.Equal("/v1/devices/register", handler.Captured[1].PathAndQuery);
        AssertSignedRequest(handler.Captured[1], material.Key, material.Device.DeviceId);
    }

    [Fact]
    public async Task TransientRequestRetryUsesANewChallengeAndStableIdempotencyKey()
    {
        using var material = TestIdentity.Create();
        var challengeNumber = 0;
        var accessAttempts = 0;
        var handler = new QueueHttpHandler(request =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("device-challenges", StringComparison.Ordinal))
            {
                challengeNumber++;
                return Json(HttpStatusCode.OK,
                    $"{{\"challengeId\":\"challenge-{challengeNumber}\",\"nonce\":\"nonce-{challengeNumber}\",\"expiresUtc\":\"{DateTimeOffset.UtcNow.AddMinutes(4):O}\"}}");
            }

            accessAttempts++;
            if (accessAttempts == 1)
                return Json(HttpStatusCode.ServiceUnavailable, "{\"code\":\"Unavailable\",\"message\":\"try later\"}");
            return Json(HttpStatusCode.OK,
                $"{{\"requestId\":\"0123456789abcdef0123456789abcdef\",\"deviceId\":\"{material.Device.DeviceId}\",\"createdUtc\":\"{DateTimeOffset.UtcNow:O}\",\"expiresUtc\":\"{DateTimeOffset.UtcNow.AddDays(7):O}\",\"status\":\"pending\",\"errorCode\":null,\"userMessage\":null}}");
        });
        using var httpClient = new HttpClient(handler);
        var client = new CloudDeviceAuthorizationClient(ValidOptions, new FakeIdentityStore(material.Identity), httpClient);

        var result = await client.RequestAccessAsync(material.Device, CancellationToken.None);

        Assert.True(result.Succeeded, $"{result.ErrorCode}: {result.UserMessage}; requests={string.Join(',', handler.Captured.Select(item => item.PathAndQuery))}");
        Assert.Equal(DeviceApprovalStatus.Pending, result.Value!.Status);
        var accessRequests = handler.Captured.Where(item => item.PathAndQuery == "/v1/access-requests").ToArray();
        Assert.Equal(2, accessRequests.Length);
        Assert.NotEqual(accessRequests[0].Headers["X-MoDi-Challenge-Id"], accessRequests[1].Headers["X-MoDi-Challenge-Id"]);
        using var firstBody = JsonDocument.Parse(accessRequests[0].Body);
        using var secondBody = JsonDocument.Parse(accessRequests[1].Body);
        Assert.Equal(
            firstBody.RootElement.GetProperty("idempotencyKey").GetString(),
            secondBody.RootElement.GetProperty("idempotencyKey").GetString());
    }

    [Fact]
    public async Task ApprovalResponseForAnotherDeviceOrRequestCannotAuthorizeSsh()
    {
        using var material = TestIdentity.Create();
        var handler = new QueueHttpHandler(request =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("device-challenges", StringComparison.Ordinal))
            {
                return Json(HttpStatusCode.OK,
                    $"{{\"challengeId\":\"challenge-1\",\"nonce\":\"nonce-1\",\"expiresUtc\":\"{DateTimeOffset.UtcNow.AddMinutes(4):O}\"}}");
            }

            var otherId = DeviceIdFactory.Create(Enumerable.Repeat((byte)0x55, 16).ToArray());
            return Json(HttpStatusCode.OK,
                $"{{\"requestId\":\"ffffffffffffffffffffffffffffffff\",\"deviceId\":\"{otherId}\",\"createdUtc\":\"{DateTimeOffset.UtcNow:O}\",\"expiresUtc\":\"{DateTimeOffset.UtcNow.AddDays(7):O}\",\"status\":\"approved\",\"errorCode\":null,\"userMessage\":null}}");
        });
        using var httpClient = new HttpClient(handler);
        var client = new CloudDeviceAuthorizationClient(ValidOptions, new FakeIdentityStore(material.Identity), httpClient);

        var result = await client.GetApprovalStatusAsync("0123456789abcdef0123456789abcdef", CancellationToken.None);
        var acquisition = await client.AcquireConnectionIdentityAsync(material.Device, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(IdentityProviderErrorCode.AuthenticationFailed, result.ErrorCode);
        Assert.NotEqual(ConnectionIdentityState.Ready, acquisition.State);
        Assert.Null(acquisition.Identity);
    }

    [Fact]
    public async Task ExactApprovedRequestCreatesOnlyPinnedRelayProfileWithoutBearerCredential()
    {
        using var material = TestIdentity.Create();
        var requestId = "0123456789abcdef0123456789abcdef";
        var handler = new QueueHttpHandler(request =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("device-challenges", StringComparison.Ordinal))
            {
                return Json(HttpStatusCode.OK,
                    $"{{\"challengeId\":\"challenge-1\",\"nonce\":\"nonce-1\",\"expiresUtc\":\"{DateTimeOffset.UtcNow.AddMinutes(4):O}\"}}");
            }

            return Json(HttpStatusCode.OK,
                $"{{\"requestId\":\"{requestId}\",\"deviceId\":\"{material.Device.DeviceId}\",\"createdUtc\":\"{DateTimeOffset.UtcNow:O}\",\"expiresUtc\":\"{DateTimeOffset.UtcNow.AddDays(7):O}\",\"status\":\"approved\",\"errorCode\":null,\"userMessage\":null}}");
        });
        using var httpClient = new HttpClient(handler);
        var client = new CloudDeviceAuthorizationClient(ValidOptions, new FakeIdentityStore(material.Identity), httpClient);

        var status = await client.GetApprovalStatusAsync(requestId, CancellationToken.None);
        var acquired = await client.AcquireConnectionIdentityAsync(material.Device, CancellationToken.None);

        Assert.True(status.Succeeded);
        Assert.Equal(DeviceApprovalStatus.Approved, status.Value!.Status);
        Assert.Equal(ConnectionIdentityState.Ready, acquired.State);
        Assert.NotNull(acquired.Identity);
        Assert.Equal(["SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"], acquired.Identity!.Server.TrustedHostFingerprints);
        Assert.Null(acquired.Identity.CredentialStatus.ExpiresUtc);
        Assert.Null(acquired.Identity.CredentialStatus.CredentialId);
        Assert.True(SshConnectionProfileValidator.TryValidate(acquired.Identity.SshProfile, out _));
    }

    [Fact]
    public async Task RefreshRechecksPermanentApprovalAndStopsReturningProfileAfterRevocation()
    {
        using var material = TestIdentity.Create();
        var requestId = "0123456789abcdef0123456789abcdef";
        var statusCount = 0;
        var challengeCount = 0;
        var handler = new QueueHttpHandler(request =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("device-challenges", StringComparison.Ordinal))
            {
                challengeCount++;
                return Json(HttpStatusCode.OK,
                    $"{{\"challengeId\":\"challenge-{challengeCount}\",\"nonce\":\"nonce-{challengeCount}\",\"expiresUtc\":\"{DateTimeOffset.UtcNow.AddMinutes(4):O}\"}}");
            }

            statusCount++;
            var state = statusCount == 1 ? "approved" : "revoked";
            return Json(HttpStatusCode.OK,
                $"{{\"requestId\":\"{requestId}\",\"deviceId\":\"{material.Device.DeviceId}\",\"createdUtc\":\"{DateTimeOffset.UtcNow:O}\",\"expiresUtc\":\"{DateTimeOffset.UtcNow.AddDays(7):O}\",\"status\":\"{state}\",\"errorCode\":null,\"userMessage\":null}}");
        });
        using var httpClient = new HttpClient(handler);
        var client = new CloudDeviceAuthorizationClient(ValidOptions, new FakeIdentityStore(material.Identity), httpClient);

        var firstStatus = await client.GetApprovalStatusAsync(requestId, CancellationToken.None);
        var initial = await client.AcquireConnectionIdentityAsync(material.Device, CancellationToken.None);
        var refreshed = await client.RefreshAuthorizationAsync(material.Device, "", CancellationToken.None);

        Assert.Equal(DeviceApprovalStatus.Approved, firstStatus.Value!.Status);
        Assert.Equal(ConnectionIdentityState.Ready, initial.State);
        Assert.Equal(ConnectionIdentityState.Revoked, refreshed.State);
        Assert.Null(refreshed.Identity);
        Assert.Equal(2, statusCount);
    }

    [Fact]
    public async Task FailedRegistrationClearsPreviouslyCachedApproval()
    {
        using var material = TestIdentity.Create();
        var requestId = "0123456789abcdef0123456789abcdef";
        var challengeCount = 0;
        var handler = new QueueHttpHandler(request =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("device-challenges", StringComparison.Ordinal))
            {
                challengeCount++;
                return Json(HttpStatusCode.OK,
                    $"{{\"challengeId\":\"challenge-{challengeCount}\",\"nonce\":\"nonce-{challengeCount}\",\"expiresUtc\":\"{DateTimeOffset.UtcNow.AddMinutes(4):O}\"}}");
            }
            if (request.RequestUri.AbsolutePath == "/v1/access-requests/" + requestId)
            {
                return Json(HttpStatusCode.OK,
                    $"{{\"requestId\":\"{requestId}\",\"deviceId\":\"{material.Device.DeviceId}\",\"createdUtc\":\"{DateTimeOffset.UtcNow:O}\",\"expiresUtc\":\"{DateTimeOffset.UtcNow.AddDays(7):O}\",\"status\":\"approved\",\"errorCode\":null,\"userMessage\":null}}");
            }
            return Json(HttpStatusCode.Forbidden, "{\"code\":\"deviceRevoked\",\"message\":\"not displayed\"}");
        });
        using var httpClient = new HttpClient(handler);
        var client = new CloudDeviceAuthorizationClient(ValidOptions, new FakeIdentityStore(material.Identity), httpClient);

        _ = await client.GetApprovalStatusAsync(requestId, CancellationToken.None);
        Assert.Equal(ConnectionIdentityState.Ready,
            (await client.AcquireConnectionIdentityAsync(material.Device, CancellationToken.None)).State);
        var registration = await client.RegisterDeviceAsync(new DeviceRegistrationRequest(material.Device), CancellationToken.None);
        var afterFailure = await client.AcquireConnectionIdentityAsync(material.Device, CancellationToken.None);

        Assert.False(registration.Succeeded);
        Assert.Equal(IdentityProviderErrorCode.AuthorizationRevoked, registration.ErrorCode);
        Assert.NotEqual(ConnectionIdentityState.Ready, afterFailure.State);
        Assert.Null(afterFailure.Identity);
    }

    [Theory]
    [InlineData("http://auth.example/")]
    [InlineData("https://user:secret@auth.example/")]
    [InlineData("https://auth.example/path?query=1")]
    [InlineData("https://auth.example/path#fragment")]
    public async Task InvalidApiBaseUrlFailsClosedWithoutSendingRequests(string apiBaseUrl)
    {
        using var material = TestIdentity.Create();
        var handler = new QueueHttpHandler(_ => throw new InvalidOperationException("No request was expected."));
        using var httpClient = new HttpClient(handler);
        var options = ValidOptions with { ApiBaseUrl = apiBaseUrl };
        var client = new CloudDeviceAuthorizationClient(options, new FakeIdentityStore(material.Identity), httpClient);

        var result = await client.RegisterDeviceAsync(new DeviceRegistrationRequest(material.Device), CancellationToken.None);

        Assert.False(result.IsConfigured);
        Assert.False(result.Succeeded);
        Assert.Equal(IdentityProviderErrorCode.ProviderNotConfigured, result.ErrorCode);
        Assert.Empty(handler.Captured);
    }

    [Theory]
    [InlineData("admin")]
    [InlineData("root")]
    public async Task SharedIdentityNeverProducesRelayProfileForAdministratorAccounts(string username)
    {
        using var material = TestIdentity.Create();
        var handler = new QueueHttpHandler(_ => throw new InvalidOperationException("No API request was expected."));
        using var httpClient = new HttpClient(handler);
        var options = ValidOptions with { RelayUsername = username };
        var client = new CloudDeviceAuthorizationClient(options, new FakeIdentityStore(material.Identity), httpClient);

        var result = await client.AcquireConnectionIdentityAsync(material.Device, CancellationToken.None);

        Assert.Equal(ConnectionIdentityState.NotConfigured, result.State);
        Assert.Null(result.Identity);
        Assert.Empty(handler.Captured);
    }

    [Fact]
    public async Task CamelCaseServiceRevocationErrorMapsToSafeRevokedState()
    {
        using var material = TestIdentity.Create();
        var handler = new QueueHttpHandler(request =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("device-challenges", StringComparison.Ordinal))
            {
                return Json(HttpStatusCode.OK,
                    $"{{\"challengeId\":\"challenge-1\",\"nonce\":\"nonce-1\",\"expiresUtc\":\"{DateTimeOffset.UtcNow.AddMinutes(4):O}\"}}");
            }

            return Json(HttpStatusCode.Forbidden, "{\"code\":\"deviceRevoked\",\"message\":\"database detail must not reach the UI\"}");
        });
        using var httpClient = new HttpClient(handler);
        var client = new CloudDeviceAuthorizationClient(ValidOptions, new FakeIdentityStore(material.Identity), httpClient);

        var result = await client.RegisterDeviceAsync(new DeviceRegistrationRequest(material.Device), CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(IdentityProviderErrorCode.AuthorizationRevoked, result.ErrorCode);
        Assert.DoesNotContain("database detail", result.UserMessage, StringComparison.Ordinal);
    }

    private static CloudDeviceAuthorizationOptions ValidOptions => new(
        "https://auth.example/",
        "relay.example",
        22,
        "modi-download",
        ["SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]);

    private static HttpResponseMessage Json(HttpStatusCode status, string body) => new(status)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json")
    };

    private static void AssertSignedRequest(CapturedRequest request, ECDsa key, string expectedKeyId)
    {
        Assert.Equal(expectedKeyId, request.Headers["X-MoDi-Key-Id"]);
        Assert.Equal("challenge-1", request.Headers["X-MoDi-Challenge-Id"]);
        Assert.Equal("nonce-1", request.Headers["X-MoDi-Nonce"]);
        var envelope = new SignedRequestEnvelope(
            request.Headers["X-MoDi-Key-Id"],
            request.Headers["X-MoDi-Challenge-Id"],
            request.Headers["X-MoDi-Nonce"],
            long.Parse(request.Headers["X-MoDi-Timestamp"], System.Globalization.CultureInfo.InvariantCulture),
            request.Headers["X-MoDi-Signature"]);
        var canonical = DeviceRequestSigner.BuildCanonicalPayload(
            request.Method, request.PathAndQuery, Encoding.UTF8.GetBytes(request.Body),
            envelope.Nonce, envelope.UnixTimestamp);
        Assert.True(key.VerifyData(
            canonical,
            Convert.FromBase64String(envelope.SignatureBase64),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence));
    }

    private sealed class FakeIdentityStore(LocalDeviceIdentity identity) : IDeviceIdentityStore
    {
        public Task<LocalDeviceIdentity> LoadOrCreateAsync(CancellationToken cancellationToken) => Task.FromResult(identity);
        public Task<bool> ForgetLocalIdentityAsync(CancellationToken cancellationToken) => Task.FromResult(false);
    }

    private sealed class QueueHttpHandler(params Func<HttpRequestMessage, HttpResponseMessage>[] responses)
        : HttpMessageHandler
    {
        private int _responseIndex;
        public List<CapturedRequest> Captured { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var body = request.Content is null
                ? ""
                : await request.Content.ReadAsStringAsync(cancellationToken);
            var headerPairs = new List<KeyValuePair<string, IEnumerable<string>>>(request.Headers);
            if (request.Content is not null)
                headerPairs.AddRange(request.Content.Headers);
            var headers = headerPairs
                .ToDictionary(pair => pair.Key, pair => string.Join(',', pair.Value), StringComparer.OrdinalIgnoreCase);
            Captured.Add(new CapturedRequest(request.Method.Method, request.RequestUri!.PathAndQuery, body, headers));
            var selected = responses[Math.Min(_responseIndex, responses.Length - 1)];
            _responseIndex++;
            return selected(request);
        }
    }

    private sealed record CapturedRequest(string Method, string PathAndQuery, string Body, Dictionary<string, string> Headers);

    private sealed class TestIdentity : IDisposable
    {
        private TestIdentity(ECDsa key, byte[] privatePem, LocalDeviceIdentity identity, DeviceIdentity device)
        {
            Key = key;
            PrivatePem = privatePem;
            Identity = identity;
            Device = device;
        }

        public ECDsa Key { get; }
        public byte[] PrivatePem { get; }
        public LocalDeviceIdentity Identity { get; }
        public DeviceIdentity Device { get; }

        public static TestIdentity Create()
        {
            var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var parameters = key.ExportParameters(false);
            var point = new byte[65];
            point[0] = 0x04;
            parameters.Q.X!.CopyTo(point, 1);
            parameters.Q.Y!.CopyTo(point, 33);
            using var blob = new MemoryStream();
            WriteSshString(blob, Encoding.ASCII.GetBytes("ecdsa-sha2-nistp256"));
            WriteSshString(blob, Encoding.ASCII.GetBytes("nistp256"));
            WriteSshString(blob, point);
            var publicKey = $"ecdsa-sha2-nistp256 {Convert.ToBase64String(blob.ToArray())} test";
            var bytes = new byte[16];
            bytes[0] = 5;
            var device = DeviceIdentity.FromOpenSshPublicKey(DeviceIdFactory.Create(bytes), "Test device", publicKey);
            var privateDer = key.ExportPkcs8PrivateKey();
            var privatePem = PemEncoding.WriteUtf8("PRIVATE KEY"u8, privateDer);
            CryptographicOperations.ZeroMemory(privateDer);
            var identity = new LocalDeviceIdentity(device, () => new MemoryStream(privatePem, writable: false));
            return new TestIdentity(key, privatePem, identity, device);
        }

        private static void WriteSshString(Stream stream, ReadOnlySpan<byte> value)
        {
            Span<byte> length = stackalloc byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
            stream.Write(length);
            stream.Write(value);
        }

        public void Dispose()
        {
            Key.Dispose();
            CryptographicOperations.ZeroMemory(PrivatePem);
        }
    }
}
