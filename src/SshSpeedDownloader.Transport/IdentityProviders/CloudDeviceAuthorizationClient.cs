using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Transport.IdentityProviders;

public sealed class CloudDeviceAuthorizationClient : ICloudDeviceAuthorizationClient
{
    private const string ApiDomain = "MODI-AUTH-DEVICE-V1";
    private const int MaximumResponseBytes = 64 * 1024;
    private static readonly Regex RequestIdPattern = new("^[0-9a-f]{32}$", RegexOptions.CultureInvariant);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _httpClient;
    private readonly IDeviceIdentityStore _identityStore;
    private readonly CloudDeviceAuthorizationOptions _options;
    private readonly Func<DateTimeOffset> _clock;

    public CloudDeviceAuthorizationClient(
        HttpClient httpClient,
        IDeviceIdentityStore identityStore,
        CloudDeviceAuthorizationOptions options,
        Func<DateTimeOffset>? clock = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _identityStore = identityStore ?? throw new ArgumentNullException(nameof(identityStore));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    public static HttpClient CreateHttpClient() =>
        new(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(4),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5)
        })
        {
            Timeout = TimeSpan.FromSeconds(8)
        };

    public async Task<IdentityProviderOperationResult<DeviceIdentity>> RegisterDeviceAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken)
    {
        if (!IsLocalDevice(device))
            return Failure<DeviceIdentity>(IdentityProviderErrorCode.AuthenticationFailed, "本机设备身份与待注册设备不匹配。");

        try
        {
            var body = JsonSerializer.SerializeToUtf8Bytes(
                new RegisterDeviceBody(device.DeviceId, device.DisplayName, device.PublicKey),
                JsonOptions);
            var response = await SendSignedAsync(HttpMethod.Post, "/v1/devices/register", body, device, cancellationToken)
                .ConfigureAwait(false);
            EnsureSuccess(response);
            using var json = JsonDocument.Parse(response.Body);
            var returnedDeviceId = RequiredString(json.RootElement, "deviceId");
            var returnedPublicKey = RequiredString(json.RootElement, "openSshPublicKey");
            var returnedFingerprint = RequiredString(json.RootElement, "publicKeyFingerprint");
            if (!returnedDeviceId.Equals(device.DeviceId, StringComparison.Ordinal) ||
                !returnedFingerprint.Equals(device.PublicKeyFingerprint, StringComparison.Ordinal) ||
                !returnedPublicKey.Equals(device.PublicKey, StringComparison.Ordinal))
                throw new InvalidDataException("Authorization service returned a different device identity.");
            return Success(device);
        }
        catch (AuthorizationApiException exception)
        {
            return Failure<DeviceIdentity>(exception.ErrorCode, exception.UserMessage);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return Failure<DeviceIdentity>(IdentityProviderErrorCode.NetworkUnavailable, "授权服务请求超时。");
        }
        catch (Exception exception) when (IsExpectedFailure(exception))
        {
            return Failure<DeviceIdentity>(IdentityProviderErrorCode.NetworkUnavailable, "无法连接云端授权服务。");
        }
    }

    public async Task<IdentityProviderOperationResult<DeviceAccessRequest>> RequestAccessAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken)
    {
        if (!IsLocalDevice(device))
            return Failure<DeviceAccessRequest>(IdentityProviderErrorCode.AuthenticationFailed, "本机设备身份与申请设备不匹配。");

        try
        {
            var state = await _identityStore.LoadRequestStateAsync(cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(state.RequestId))
            {
                var existing = await GetApprovalStatusAsync(state.RequestId, cancellationToken).ConfigureAwait(false);
                if (existing.Succeeded &&
                    existing.Value?.Status is DeviceApprovalStatus.Pending or DeviceApprovalStatus.Approved)
                    return existing;
                if (existing.ErrorCode == IdentityProviderErrorCode.AuthorizationRevoked)
                    return existing;
                if (existing.Succeeded &&
                    existing.Value?.Status is DeviceApprovalStatus.Rejected or DeviceApprovalStatus.Expired)
                {
                    await _identityStore.ClearRequestStateAsync(cancellationToken).ConfigureAwait(false);
                    state = new DeviceRequestState(null, null);
                }
                else if (!existing.Succeeded)
                {
                    return existing;
                }
            }

            var idempotencyKey = state.IdempotencyKey ?? Guid.NewGuid().ToString("N");
            if (state.IdempotencyKey is null)
                await _identityStore.SaveRequestStateAsync(
                    new DeviceRequestState(idempotencyKey, null),
                    cancellationToken).ConfigureAwait(false);

            var body = JsonSerializer.SerializeToUtf8Bytes(
                new RequestAccessBody(idempotencyKey),
                JsonOptions);
            var response = await SendSignedAsync(HttpMethod.Post, "/v1/access-requests", body, device, cancellationToken)
                .ConfigureAwait(false);
            EnsureSuccess(response);
            var request = ParseAccessRequest(response.Body, device.DeviceId);
            await _identityStore.SaveRequestStateAsync(
                new DeviceRequestState(idempotencyKey, request.RequestId),
                cancellationToken).ConfigureAwait(false);
            return Success(request);
        }
        catch (AuthorizationApiException exception)
        {
            return Failure<DeviceAccessRequest>(exception.ErrorCode, exception.UserMessage);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return Failure<DeviceAccessRequest>(IdentityProviderErrorCode.NetworkUnavailable, "授权服务请求超时。");
        }
        catch (Exception exception) when (IsExpectedFailure(exception))
        {
            return Failure<DeviceAccessRequest>(IdentityProviderErrorCode.NetworkUnavailable, "无法连接云端授权服务。");
        }
    }

    public async Task<IdentityProviderOperationResult<DeviceAccessRequest>> GetApprovalStatusAsync(
        string requestId,
        CancellationToken cancellationToken)
    {
        if (!RequestIdPattern.IsMatch(requestId ?? ""))
            return Failure<DeviceAccessRequest>(IdentityProviderErrorCode.Unknown, "申请编号无效。");

        var device = _identityStore.Device;
        if (!IsLocalDevice(device))
            return Failure<DeviceAccessRequest>(IdentityProviderErrorCode.AuthenticationFailed, "本机设备身份不可用。");

        try
        {
            var response = await SendSignedAsync(
                HttpMethod.Get,
                "/v1/access-requests/" + requestId,
                [],
                device,
                cancellationToken).ConfigureAwait(false);
            EnsureSuccess(response);
            return Success(ParseAccessRequest(response.Body, device.DeviceId));
        }
        catch (AuthorizationApiException exception)
        {
            return Failure<DeviceAccessRequest>(exception.ErrorCode, exception.UserMessage);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return Failure<DeviceAccessRequest>(IdentityProviderErrorCode.NetworkUnavailable, "授权服务请求超时。");
        }
        catch (Exception exception) when (IsExpectedFailure(exception))
        {
            return Failure<DeviceAccessRequest>(IdentityProviderErrorCode.NetworkUnavailable, "无法连接云端授权服务。");
        }
    }

    public async Task<IdentityProviderOperationResult<DeviceAccessRequest>> GetCurrentAccessRequestAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken)
    {
        if (!IsLocalDevice(device))
            return Failure<DeviceAccessRequest>(IdentityProviderErrorCode.AuthenticationFailed, "本机设备身份不可用。");

        try
        {
            var state = await _identityStore.LoadRequestStateAsync(cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(state.RequestId))
            {
                if (!string.IsNullOrWhiteSpace(state.IdempotencyKey))
                    return await RequestAccessAsync(device, cancellationToken).ConfigureAwait(false);
                return Failure<DeviceAccessRequest>(
                    IdentityProviderErrorCode.DeviceNotRegistered,
                    "尚未申请使用；点击“申请使用下载器”提交申请。");
            }
            return await GetApprovalStatusAsync(state.RequestId, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (IsExpectedFailure(exception))
        {
            return Failure<DeviceAccessRequest>(IdentityProviderErrorCode.NetworkUnavailable, "无法读取本机授权状态。");
        }
    }

    public async Task<ConnectionIdentityResult> AcquireConnectionIdentityAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken)
    {
        if (!IsLocalDevice(device))
            return IdentityFailure(ConnectionIdentityState.Failed, IdentityProviderErrorCode.AuthenticationFailed, "本机设备身份不可用。");

        var result = await GetCurrentAccessRequestAsync(device, cancellationToken).ConfigureAwait(false);
        if (!result.Succeeded || result.Value is null)
        {
            var state = result.ErrorCode switch
            {
                IdentityProviderErrorCode.AuthorizationRevoked => ConnectionIdentityState.Revoked,
                IdentityProviderErrorCode.DeviceNotRegistered => ConnectionIdentityState.NotConfigured,
                IdentityProviderErrorCode.NetworkUnavailable => ConnectionIdentityState.Failed,
                _ => ConnectionIdentityState.Failed
            };
            return IdentityFailure(state, result.ErrorCode, result.UserMessage ?? "无法获取云端授权状态。");
        }

        var request = result.Value;
        var mappedState = request.Status switch
        {
            DeviceApprovalStatus.Pending => ConnectionIdentityState.Pending,
            DeviceApprovalStatus.Rejected => ConnectionIdentityState.Rejected,
            DeviceApprovalStatus.Expired => ConnectionIdentityState.Expired,
            DeviceApprovalStatus.Revoked => ConnectionIdentityState.Revoked,
            DeviceApprovalStatus.Approved => ConnectionIdentityState.Ready,
            _ => ConnectionIdentityState.Failed
        };
        if (mappedState != ConnectionIdentityState.Ready)
            return new ConnectionIdentityResult(
                mappedState,
                null,
                request,
                request.ErrorCode,
                request.UserMessage);

        var profile = new SshConnectionProfile(
            _options.Relay.Host,
            _options.Relay.Port,
            _options.Relay.Username,
            "",
            null)
        {
            PrivateKeyIdentityId = device.DeviceId,
            PrivateKeyStreamProvider = _identityStore.OpenPrivateKeyStream,
            TrustedHostFingerprints = _options.Relay.TrustedHostFingerprints,
            SupportsRemoteCommandDiagnostics = false
        };
        var connectionIdentity = new ConnectionIdentity(
            device.DeviceId,
            _options.Relay,
            profile,
            new ConnectionCredentialStatus(true, null, false));
        return new ConnectionIdentityResult(
            ConnectionIdentityState.Ready,
            connectionIdentity,
            request,
            null,
            request.UserMessage);
    }

    public Task<ConnectionIdentityResult> RefreshAuthorizationAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken) =>
        AcquireConnectionIdentityAsync(device, cancellationToken);

    public async Task<IdentityProviderOperationResult<bool>> ForgetLocalIdentityAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken)
    {
        if (!IsLocalDevice(device))
            return Failure<bool>(IdentityProviderErrorCode.AuthenticationFailed, "本机设备身份与待清除身份不匹配。");
        try
        {
            await _identityStore.ForgetLocalIdentityAsync(cancellationToken).ConfigureAwait(false);
            return Success(true);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (IsExpectedFailure(exception))
        {
            return Failure<bool>(IdentityProviderErrorCode.Unknown, "无法清除本机设备身份。");
        }
    }

    private async Task<ApiResponse> SendSignedAsync(
        HttpMethod method,
        string requestTarget,
        byte[] body,
        DeviceIdentity device,
        CancellationToken cancellationToken)
    {
        var challengeBody = JsonSerializer.SerializeToUtf8Bytes(
            new DeviceChallengeBody(device.DeviceId, device.PublicKeyFingerprint),
            JsonOptions);
        var challengeResponse = await SendRawAsync(
            HttpMethod.Post,
            "/v1/device-challenges",
            challengeBody,
            cancellationToken).ConfigureAwait(false);
        EnsureSuccess(challengeResponse);
        var challenge = ParseChallenge(challengeResponse.Body);
        var timestamp = _clock().ToUnixTimeSeconds();
        var canonical = DeviceRequestCanonicalizer.Create(
            method.Method,
            requestTarget,
            body,
            challenge.Nonce,
            timestamp);
        byte[] signature;
        try
        {
            signature = _identityStore.Sign(canonical);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }

        try
        {
            return await SendRawAsync(
                method,
                requestTarget,
                body,
                cancellationToken,
                device.DeviceId,
                challenge.ChallengeId,
                challenge.Nonce,
                timestamp,
                Convert.ToBase64String(signature)).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private async Task<ApiResponse> SendRawAsync(
        HttpMethod method,
        string requestTarget,
        byte[] body,
        CancellationToken cancellationToken,
        string? keyId = null,
        string? challengeId = null,
        string? nonce = null,
        long timestamp = 0,
        string? signature = null)
    {
        using var request = new HttpRequestMessage(
            method,
            new Uri(_options.ApiBaseUri, requestTarget.TrimStart('/')));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("MoDi-Downloader-Windows");
        if (keyId is not null)
        {
            request.Headers.TryAddWithoutValidation("X-MoDi-Key-Id", keyId);
            request.Headers.TryAddWithoutValidation("X-MoDi-Challenge-Id", challengeId);
            request.Headers.TryAddWithoutValidation("X-MoDi-Nonce", nonce);
            request.Headers.TryAddWithoutValidation(
                "X-MoDi-Timestamp",
                timestamp.ToString(CultureInfo.InvariantCulture));
            request.Headers.TryAddWithoutValidation("X-MoDi-Signature", signature);
        }
        if (body.Length > 0)
        {
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }

        using var response = await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        var responseBytes = await ReadBoundedBodyAsync(response.Content, cancellationToken).ConfigureAwait(false);
        return new ApiResponse(response.StatusCode, responseBytes);
    }

    private static async Task<byte[]> ReadBoundedBodyAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is > MaximumResponseBytes)
            throw new InvalidDataException("Authorization response exceeds the size limit.");
        await using var input = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[4096];
        try
        {
            while (true)
            {
                var count = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (count == 0)
                    break;
                if (output.Length + count > MaximumResponseBytes)
                    throw new InvalidDataException("Authorization response exceeds the size limit.");
                output.Write(buffer, 0, count);
            }
            return output.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static DeviceChallenge ParseChallenge(byte[] body)
    {
        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;
        var challengeId = RequiredString(root, "challengeId");
        var nonce = RequiredString(root, "nonce");
        if (!Regex.IsMatch(challengeId, "^[A-Za-z0-9_-]{1,128}$", RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(nonce, "^[A-Za-z0-9_-]{1,128}$", RegexOptions.CultureInvariant))
            throw new JsonException("Authorization challenge is invalid.");
        return new DeviceChallenge(challengeId, nonce);
    }

    private static DeviceAccessRequest ParseAccessRequest(byte[] body, string expectedDeviceId)
    {
        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;
        var requestId = RequiredString(root, "requestId");
        var deviceId = RequiredString(root, "deviceId");
        if (!RequestIdPattern.IsMatch(requestId) || !deviceId.Equals(expectedDeviceId, StringComparison.Ordinal))
            throw new JsonException("Authorization request identity is invalid.");
        var status = RequiredString(root, "status") switch
        {
            "pending" => DeviceApprovalStatus.Pending,
            "approved" => DeviceApprovalStatus.Approved,
            "rejected" => DeviceApprovalStatus.Rejected,
            "expired" => DeviceApprovalStatus.Expired,
            "revoked" => DeviceApprovalStatus.Revoked,
            _ => throw new JsonException("Authorization status is invalid.")
        };
        return new DeviceAccessRequest(
            requestId,
            deviceId,
            ParseTimestamp(RequiredString(root, "createdUtc")),
            ParseTimestamp(RequiredString(root, "expiresUtc")),
            status,
            ParseErrorCode(root),
            OptionalString(root, "userMessage"));
    }

    private static DateTimeOffset ParseTimestamp(string value) =>
        DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var result)
            ? result
            : throw new JsonException("Authorization timestamp is invalid.");

    private static IdentityProviderErrorCode? ParseErrorCode(JsonElement root)
    {
        var error = OptionalString(root, "errorCode");
        if (error is null)
            return null;
        return error switch
        {
            "deviceRevoked" => IdentityProviderErrorCode.AuthorizationRevoked,
            "deviceNotRegistered" => IdentityProviderErrorCode.DeviceNotRegistered,
            "requestNotFound" => IdentityProviderErrorCode.DeviceNotRegistered,
            "invalidSignature" or "device_key_conflict" => IdentityProviderErrorCode.AuthenticationFailed,
            "rate_limited" or "service_unavailable" => IdentityProviderErrorCode.NetworkUnavailable,
            _ => IdentityProviderErrorCode.Unknown
        };
    }

    private static void EnsureSuccess(ApiResponse response)
    {
        if ((int)response.StatusCode is >= 200 and < 300)
            return;
        var code = "unknown";
        var message = "授权服务拒绝了请求。";
        try
        {
            using var document = JsonDocument.Parse(response.Body);
            code = OptionalString(document.RootElement, "code") ?? code;
            message = OptionalString(document.RootElement, "message") ?? message;
        }
        catch (JsonException)
        {
        }
        throw new AuthorizationApiException(MapErrorCode(code, response.StatusCode), message);
    }

    private static IdentityProviderErrorCode MapErrorCode(string code, HttpStatusCode statusCode) =>
        code switch
        {
            "deviceRevoked" => IdentityProviderErrorCode.AuthorizationRevoked,
            "deviceNotRegistered" => IdentityProviderErrorCode.DeviceNotRegistered,
            "challengeExpired" => IdentityProviderErrorCode.NetworkUnavailable,
            "invalidSignature" or "device_key_conflict" => IdentityProviderErrorCode.AuthenticationFailed,
            "rate_limited" or "service_unavailable" => IdentityProviderErrorCode.NetworkUnavailable,
            _ when statusCode is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable => IdentityProviderErrorCode.NetworkUnavailable,
            _ => IdentityProviderErrorCode.Unknown
        };

    private static string RequiredString(JsonElement value, string propertyName)
    {
        if (!value.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.String)
            throw new JsonException("Authorization response is missing a required field.");
        return property.GetString() ?? throw new JsonException("Authorization response contains a null field.");
    }

    private static string? OptionalString(JsonElement value, string propertyName)
    {
        if (!value.TryGetProperty(propertyName, out var property) || property.ValueKind == JsonValueKind.Null)
            return null;
        if (property.ValueKind != JsonValueKind.String)
            throw new JsonException("Authorization response has an invalid field.");
        return property.GetString();
    }

    private bool IsLocalDevice(DeviceIdentity device) =>
        device is not null &&
        device.DeviceId.Equals(_identityStore.Device.DeviceId, StringComparison.Ordinal) &&
        device.PublicKeyFingerprint.Equals(_identityStore.Device.PublicKeyFingerprint, StringComparison.Ordinal);

    private static bool IsExpectedFailure(Exception exception) =>
        exception is HttpRequestException or IOException or JsonException or FormatException or
            CryptographicException or ArgumentException or InvalidOperationException;

    private static ConnectionIdentityResult IdentityFailure(
        ConnectionIdentityState state,
        IdentityProviderErrorCode? errorCode,
        string message) =>
        new(state, null, null, errorCode, message);

    private static IdentityProviderOperationResult<T> Failure<T>(
        IdentityProviderErrorCode code,
        string message) =>
        new(true, false, default, code, message);

    private static IdentityProviderOperationResult<T> Success<T>(T value) =>
        new(true, true, value, null, null);

    private sealed record DeviceChallengeBody(
        [property: JsonPropertyName("deviceId")] string DeviceId,
        [property: JsonPropertyName("publicKeyFingerprint")] string PublicKeyFingerprint);

    private sealed record RegisterDeviceBody(
        [property: JsonPropertyName("deviceId")] string DeviceId,
        [property: JsonPropertyName("displayName")] string DisplayName,
        [property: JsonPropertyName("openSshPublicKey")] string PublicKey);

    private sealed record RequestAccessBody(
        [property: JsonPropertyName("idempotencyKey")] string IdempotencyKey);

    private sealed record DeviceChallenge(string ChallengeId, string Nonce);
    private sealed record ApiResponse(HttpStatusCode StatusCode, byte[] Body);

    private sealed class AuthorizationApiException(
        IdentityProviderErrorCode errorCode,
        string userMessage) : Exception("Cloud authorization request failed.")
    {
        public IdentityProviderErrorCode ErrorCode { get; } = errorCode;
        public string UserMessage { get; } = userMessage;
    }
}
