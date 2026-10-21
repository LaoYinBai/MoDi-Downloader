using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SshSpeedDownloader.Core;
using SshSpeedDownloader.Transport.IdentityProviders;

namespace SshSpeedDownloader.Tests;

[SupportedOSPlatform("windows")]
public sealed class CloudDeviceAuthorizationClientTests
{
    [Fact]
    public async Task ExplicitApplicationRegistersAndCreatesOnePendingRequest()
    {
        using var directory = new TemporaryDirectory();
        var store = new WindowsDeviceIdentityStore(Path.Combine(directory.Path, "identity.json"), "Test Downloader");
        var device = await store.LoadOrCreateAsync();
        var handler = new ScriptedAuthorizationHandler(device);
        using var httpClient = new HttpClient(handler);
        var client = new CloudDeviceAuthorizationClient(httpClient, store, Options);
        var provider = new CloudApprovedIdentityProvider(client, device);

        var result = await provider.RequestAccessAsync(CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal(DeviceApprovalStatus.Pending, result.Value?.Status);
        Assert.Equal(
            ["/v1/device-challenges", "/v1/devices/register", "/v1/device-challenges", "/v1/access-requests"],
            handler.Requests.Select(request => request.Path));
        Assert.All(
            handler.Requests.Where(request => request.Path != "/v1/device-challenges"),
            request =>
            {
                Assert.Equal(device.DeviceId, request.KeyId);
                Assert.False(string.IsNullOrWhiteSpace(request.ChallengeId));
                Assert.False(string.IsNullOrWhiteSpace(request.Nonce));
                Assert.False(string.IsNullOrWhiteSpace(request.Signature));
            });
        Assert.Equal(
            new string('b', 32),
            (await store.LoadRequestStateAsync()).RequestId);
    }

    [Fact]
    public async Task ApprovedStatusIsTheOnlyStateThatCreatesARestrictedSshIdentity()
    {
        using var directory = new TemporaryDirectory();
        var store = new WindowsDeviceIdentityStore(Path.Combine(directory.Path, "identity.json"), "Test Downloader");
        var device = await store.LoadOrCreateAsync();
        var handler = new ScriptedAuthorizationHandler(device) { RequestStatus = "approved" };
        using var httpClient = new HttpClient(handler);
        var client = new CloudDeviceAuthorizationClient(httpClient, store, Options);
        await store.SaveRequestStateAsync(new DeviceRequestState(new string('a', 32), new string('b', 32)));

        var acquisition = await client.AcquireConnectionIdentityAsync(device, CancellationToken.None);

        Assert.Equal(ConnectionIdentityState.Ready, acquisition.State);
        Assert.Equal("modi-relay", acquisition.Identity?.SshProfile.Username);
        Assert.Equal("39.105.70.140", acquisition.Identity?.SshProfile.Host);
        Assert.Equal(device.DeviceId, acquisition.Identity?.SshProfile.PrivateKeyIdentityId);
        Assert.Equal("", acquisition.Identity?.SshProfile.PrivateKeyPath);
        Assert.NotNull(acquisition.Identity?.SshProfile.PrivateKeyStreamProvider);
        Assert.Contains(
            "/v1/access-requests/" + new string('b', 32),
            handler.Requests.Last().Path);
    }

    [Fact]
    public async Task PendingAndRejectedResponsesNeverProvideAnSshIdentity()
    {
        using var directory = new TemporaryDirectory();
        var store = new WindowsDeviceIdentityStore(Path.Combine(directory.Path, "identity.json"), "Test Downloader");
        var device = await store.LoadOrCreateAsync();
        await store.SaveRequestStateAsync(new DeviceRequestState(new string('a', 32), new string('b', 32)));
        var handler = new ScriptedAuthorizationHandler(device) { RequestStatus = "pending" };
        using var httpClient = new HttpClient(handler);
        var client = new CloudDeviceAuthorizationClient(httpClient, store, Options);

        var pending = await client.AcquireConnectionIdentityAsync(device, CancellationToken.None);
        handler.RequestStatus = "rejected";
        var rejected = await client.AcquireConnectionIdentityAsync(device, CancellationToken.None);

        Assert.Equal(ConnectionIdentityState.Pending, pending.State);
        Assert.Null(pending.Identity);
        Assert.Equal(ConnectionIdentityState.Rejected, rejected.State);
        Assert.Null(rejected.Identity);
    }

    [Fact]
    public async Task AuthorizationServiceFailureNeverReturnsAnSshIdentityOrSubmitsAnAccessRequest()
    {
        using var directory = new TemporaryDirectory();
        var store = new WindowsDeviceIdentityStore(Path.Combine(directory.Path, "identity.json"), "Test Downloader");
        var device = await store.LoadOrCreateAsync();
        var handler = new ScriptedAuthorizationHandler(device)
        {
            ChallengeStatusCode = HttpStatusCode.ServiceUnavailable
        };
        using var httpClient = new HttpClient(handler);
        var client = new CloudDeviceAuthorizationClient(httpClient, store, Options);
        var provider = new CloudApprovedIdentityProvider(client, device);

        var result = await provider.RequestAccessAsync(CancellationToken.None);
        var acquisition = await client.AcquireConnectionIdentityAsync(device, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(IdentityProviderErrorCode.NetworkUnavailable, result.ErrorCode);
        Assert.Null(acquisition.Identity);
        Assert.Equal(ConnectionIdentityState.NotConfigured, acquisition.State);
        Assert.DoesNotContain(handler.Requests, request => request.Path == "/v1/access-requests");
    }

    [Theory]
    [InlineData("expired", ConnectionIdentityState.Expired)]
    [InlineData("revoked", ConnectionIdentityState.Revoked)]
    public async Task ExpiredAndRevokedStatesFailClosed(string status, ConnectionIdentityState expected)
    {
        using var directory = new TemporaryDirectory();
        var store = new WindowsDeviceIdentityStore(Path.Combine(directory.Path, "identity.json"), "Test Downloader");
        var device = await store.LoadOrCreateAsync();
        await store.SaveRequestStateAsync(new DeviceRequestState(new string('a', 32), new string('b', 32)));
        using var http = new HttpClient(new ScriptedAuthorizationHandler(device) { RequestStatus = status });
        var client = new CloudDeviceAuthorizationClient(http, store, Options);

        var result = await client.AcquireConnectionIdentityAsync(device, CancellationToken.None);

        Assert.Equal(expected, result.State);
        Assert.Null(result.Identity);
    }

    [Fact]
    public async Task ApprovalDoesNotExpireWithTheOriginalPendingRequestDeadline()
    {
        using var directory = new TemporaryDirectory();
        var store = new WindowsDeviceIdentityStore(Path.Combine(directory.Path, "identity.json"), "Test Downloader");
        var device = await store.LoadOrCreateAsync();
        await store.SaveRequestStateAsync(new DeviceRequestState(new string('a', 32), new string('b', 32)));
        using var http = new HttpClient(new ScriptedAuthorizationHandler(device) { RequestStatus = "approved" });
        var client = new CloudDeviceAuthorizationClient(http, store, Options,
            () => new DateTimeOffset(2040, 1, 1, 0, 0, 0, TimeSpan.Zero));

        var result = await client.AcquireConnectionIdentityAsync(device, CancellationToken.None);

        Assert.Equal(ConnectionIdentityState.Ready, result.State);
        Assert.Null(result.Identity!.CredentialStatus.ExpiresUtc);
    }

    private static CloudDeviceAuthorizationOptions Options => new(
        new Uri("https://auth.modiconnect.cn/"),
        new ServerConnectionConfiguration(
            "39.105.70.140",
            22,
            "modi-relay",
            [
                "SHA256:mlPaG+lfjBo92T/OG7fVrVz4sxY+rM+1hTxT+hY9X4k",
                "SHA256:FjMNC1WcRbxcpiNwiVzEauHETLOWagnixLgQtWoSNyk",
                "SHA256:rkxyIaeyapIwt1zGy+JPffafL8ClWOYRQIvkvuFiGls"
            ]));

    private sealed class ScriptedAuthorizationHandler(DeviceIdentity device) : HttpMessageHandler
    {
        private int _challengeCount;

        public List<RecordedRequest> Requests { get; } = [];
        public string RequestStatus { get; set; } = "pending";
        public HttpStatusCode ChallengeStatusCode { get; set; } = HttpStatusCode.OK;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var path = request.RequestUri?.PathAndQuery ?? "";
            var body = request.Content is null
                ? ""
                : await request.Content.ReadAsStringAsync(cancellationToken);
            if (path != "/v1/device-challenges")
                VerifyDeviceSignature(request, path, Encoding.UTF8.GetBytes(body));
            Requests.Add(new RecordedRequest(
                path,
                request.Method,
                body,
                request.Headers.TryGetValues("X-MoDi-Key-Id", out var keyId) ? keyId.Single() : null,
                request.Headers.TryGetValues("X-MoDi-Challenge-Id", out var challengeId) ? challengeId.Single() : null,
                request.Headers.TryGetValues("X-MoDi-Nonce", out var nonce) ? nonce.Single() : null,
                request.Headers.TryGetValues("X-MoDi-Signature", out var signature) ? signature.Single() : null));

            if (path == "/v1/device-challenges")
            {
                if (ChallengeStatusCode != HttpStatusCode.OK)
                    return Json(ChallengeStatusCode, "{\"code\":\"service_unavailable\",\"message\":\"Unavailable.\"}");
                var challenge = ++_challengeCount;
                return Json(HttpStatusCode.OK,
                    "{\"challengeId\":\"challenge-" + challenge + "\",\"nonce\":\"nonce-" + challenge +
                    "\",\"expiresUtc\":\"2026-10-19T00:00:00Z\"}");
            }

            if (path == "/v1/devices/register")
            {
                using var payload = JsonDocument.Parse(body);
                var root = payload.RootElement;
                var registeredDevice = DeviceIdentity.FromOpenSshPublicKey(
                    root.GetProperty("deviceId").GetString()!,
                    root.GetProperty("displayName").GetString()!,
                    root.GetProperty("openSshPublicKey").GetString()!);
                return Json(HttpStatusCode.OK,
                    JsonSerializer.Serialize(new
                    {
                        deviceId = registeredDevice.DeviceId,
                        displayName = registeredDevice.DisplayName,
                        openSshPublicKey = registeredDevice.PublicKey,
                        publicKeyFingerprint = registeredDevice.PublicKeyFingerprint,
                        createdUtc = "2026-10-19T00:00:00Z",
                        status = "registered"
                    }));
            }

            if (path == "/v1/access-requests")
                return AccessRequest(request.Headers.GetValues("X-MoDi-Key-Id").Single());

            if (path == "/v1/access-requests/" + new string('b', 32))
                return AccessRequest(request.Headers.GetValues("X-MoDi-Key-Id").Single());

            return Json(HttpStatusCode.NotFound, "{\"code\":\"not_found\",\"message\":\"Not found.\"}");
        }

        private HttpResponseMessage AccessRequest(string deviceId) => Json(
            HttpStatusCode.OK,
            JsonSerializer.Serialize(new
            {
                requestId = new string('b', 32),
                deviceId,
                createdUtc = "2026-10-19T00:00:00Z",
                expiresUtc = "2026-11-18T00:00:00Z",
                status = RequestStatus,
                errorCode = (string?)null,
                userMessage = "Server status."
            }));

        private static HttpResponseMessage Json(HttpStatusCode status, string json) => new(status)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        private void VerifyDeviceSignature(
            HttpRequestMessage request,
            string requestTarget,
            byte[] body)
        {
            var deviceId = request.Headers.GetValues("X-MoDi-Key-Id").Single();
            var nonce = request.Headers.GetValues("X-MoDi-Nonce").Single();
            var timestamp = long.Parse(
                request.Headers.GetValues("X-MoDi-Timestamp").Single(),
                System.Globalization.CultureInfo.InvariantCulture);
            var signature = Convert.FromBase64String(
                request.Headers.GetValues("X-MoDi-Signature").Single());
            Assert.Equal(device.DeviceId, deviceId);
            var canonical = DeviceRequestCanonicalizer.Create(
                request.Method.Method,
                requestTarget,
                body,
                nonce,
                timestamp);
            using var publicKey = ImportOpenSshP256PublicKey(device.PublicKey);
            Assert.True(publicKey.VerifyData(
                canonical,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence));
        }

        private static ECDsa ImportOpenSshP256PublicKey(string publicKey)
        {
            var fields = publicKey.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var blob = Convert.FromBase64String(fields[1]);
            var offset = 0;
            ReadSshString(blob, ref offset);
            ReadSshString(blob, ref offset);
            var point = ReadSshString(blob, ref offset);
            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = point.AsSpan(1, 32).ToArray(),
                    Y = point.AsSpan(33, 32).ToArray()
                }
            });
        }

        private static byte[] ReadSshString(byte[] blob, ref int offset)
        {
            var length = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(offset, 4));
            offset += 4;
            var value = blob.AsSpan(offset, (int)length).ToArray();
            offset += (int)length;
            return value;
        }
    }

    private sealed record RecordedRequest(
        string Path,
        HttpMethod Method,
        string Body,
        string? KeyId,
        string? ChallengeId,
        string? Nonce,
        string? Signature);

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            "modi-cloud-auth-" + Guid.NewGuid().ToString("N"));

        public TemporaryDirectory() => Directory.CreateDirectory(Path);

        public void Dispose()
        {
            if (Directory.Exists(Path))
                Directory.Delete(Path, recursive: true);
        }
    }
}
