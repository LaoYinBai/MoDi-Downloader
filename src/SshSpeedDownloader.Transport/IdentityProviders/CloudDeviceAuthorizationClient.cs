using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Transport.IdentityProviders;

public sealed class CloudDeviceAuthorizationClient : ICloudDeviceAuthorizationClient, IDisposable
{
    private const int MaximumBodyBytes = 16 * 1024;
    private const int MaximumAttempts = 2;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan[] RetryDelays = [TimeSpan.FromMilliseconds(150), TimeSpan.FromMilliseconds(400)];
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 8,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false) }
    };

    private readonly CloudDeviceAuthorizationOptions _options;
    private readonly IDeviceIdentityStore _identityStore;
    private readonly HttpClient _httpClient;
    private readonly TimeProvider _timeProvider;
    private readonly bool _ownsHttpClient;
    private readonly ConcurrentDictionary<string, string> _idempotencyKeys = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, bool> _approvalStates = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _latestRequestIds = new(StringComparer.Ordinal);

    public CloudDeviceAuthorizationClient(
        CloudDeviceAuthorizationOptions options,
        IDeviceIdentityStore identityStore,
        HttpClient? httpClient = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(identityStore);
        _options = options;
        _identityStore = identityStore;
        _timeProvider = timeProvider ?? TimeProvider.System;
        if (httpClient is null)
        {
            _httpClient = new HttpClient(new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                ConnectTimeout = TimeSpan.FromSeconds(5),
                PooledConnectionLifetime = TimeSpan.FromMinutes(5)
            })
            {
                Timeout = Timeout.InfiniteTimeSpan
            };
            _ownsHttpClient = true;
        }
        else
        {
            _httpClient = httpClient;
        }
    }

    public async Task<IdentityProviderOperationResult<DeviceIdentity>> RegisterDeviceAsync(
        DeviceRegistrationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!TryGetApiBaseUri(out _))
            return NotConfigured<DeviceIdentity>("云端鉴权 HTTPS 地址尚未配置或无效。 ");

        try
        {
            await EnsureLocalIdentityMatchesAsync(request.Device, cancellationToken).ConfigureAwait(false);
            _approvalStates[request.Device.DeviceId] = false;
            var body = JsonSerializer.SerializeToUtf8Bytes(new RegisterDeviceCommandDto(
                request.Device.DeviceId,
                request.Device.DisplayName,
                request.Device.PublicKey), JsonOptions);
            try
            {
                var response = await SendSignedJsonAsync<RegisteredDeviceDto>(
                    request.Device, HttpMethod.Post, "/v1/devices/register", body, cancellationToken).ConfigureAwait(false);
                var returned = DeviceIdentity.FromOpenSshPublicKey(
                    response.DeviceId, response.DisplayName, response.OpenSshPublicKey);
                if (!SameDevice(request.Device, returned) ||
                    !StringComparer.Ordinal.Equals(request.Device.PublicKey, returned.PublicKey) ||
                    !StringComparer.Ordinal.Equals(request.Device.PublicKeyFingerprint, response.PublicKeyFingerprint))
                {
                    throw new AuthorizationClientException(
                        IdentityProviderErrorCode.AuthenticationFailed,
                        "云端登记结果与本机设备密钥不一致。");
                }

                _approvalStates[request.Device.DeviceId] = false;
                return ConfiguredSuccess(request.Device);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(body);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return Failure<DeviceIdentity>(exception);
        }
    }

    public async Task<IdentityProviderOperationResult<DeviceAccessRequest>> RequestAccessAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(device);
        if (!TryGetApiBaseUri(out _))
            return NotConfigured<DeviceAccessRequest>("云端鉴权 HTTPS 地址尚未配置或无效。 ");

        try
        {
            await EnsureLocalIdentityMatchesAsync(device, cancellationToken).ConfigureAwait(false);
            _approvalStates[device.DeviceId] = false;
            var idempotencyKey = _idempotencyKeys.GetOrAdd(
                device.DeviceId,
                static _ => Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture));
            var body = JsonSerializer.SerializeToUtf8Bytes(new RequestAccessCommandDto(idempotencyKey), JsonOptions);
            try
            {
                var response = await SendSignedJsonAsync<AccessRequestDto>(
                    device, HttpMethod.Post, "/v1/access-requests", body, cancellationToken).ConfigureAwait(false);
                var request = ConvertAccessRequest(response);
                if (!StringComparer.Ordinal.Equals(request.DeviceId, device.DeviceId))
                    throw new AuthorizationClientException(
                        IdentityProviderErrorCode.AuthenticationFailed,
                        "云端审批结果不属于本机设备。");
                _approvalStates[device.DeviceId] = request.Status == DeviceApprovalStatus.Approved;
                _latestRequestIds[device.DeviceId] = request.RequestId;
                if (request.Status is DeviceApprovalStatus.Rejected or DeviceApprovalStatus.Expired)
                    _idempotencyKeys.TryRemove(device.DeviceId, out _);
                return ConfiguredSuccess(request);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(body);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return Failure<DeviceAccessRequest>(exception);
        }
    }

    public async Task<IdentityProviderOperationResult<DeviceAccessRequest>> GetApprovalStatusAsync(
        string requestId,
        CancellationToken cancellationToken)
    {
        if (!IsValidRequestId(requestId))
        {
            return new IdentityProviderOperationResult<DeviceAccessRequest>(
                true, false, null, IdentityProviderErrorCode.RequestNotFound,
                "设备申请编号无效或已不存在。");
        }
        if (!TryGetApiBaseUri(out _))
            return NotConfigured<DeviceAccessRequest>("云端鉴权 HTTPS 地址尚未配置或无效。 ");

        try
        {
            var local = await _identityStore.LoadOrCreateAsync(cancellationToken).ConfigureAwait(false);
            var device = local.DeviceIdentity;
            var response = await SendSignedJsonAsync<AccessRequestDto>(
                device, HttpMethod.Get, $"/v1/access-requests/{requestId}", [], cancellationToken).ConfigureAwait(false);
            var result = ConvertAccessRequest(response);
            if (!StringComparer.Ordinal.Equals(result.RequestId, requestId) ||
                !StringComparer.Ordinal.Equals(result.DeviceId, device.DeviceId))
            {
                throw new AuthorizationClientException(
                    IdentityProviderErrorCode.AuthenticationFailed,
                    "云端审批结果与本机设备申请不匹配。");
            }
            _approvalStates[device.DeviceId] = result.Status == DeviceApprovalStatus.Approved;
            _latestRequestIds[device.DeviceId] = result.RequestId;
            if (result.Status == DeviceApprovalStatus.Rejected || result.Status == DeviceApprovalStatus.Expired)
                _idempotencyKeys.TryRemove(device.DeviceId, out _);
            return ConfiguredSuccess(result);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return Failure<DeviceAccessRequest>(exception);
        }
    }

    public async Task<ConnectionIdentityResult> AcquireConnectionIdentityAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!TryGetApiBaseUri(out _) || !_options.TryGetServerConfiguration(out var server))
        {
            return new ConnectionIdentityResult(
                ConnectionIdentityState.NotConfigured, null, null, IdentityProviderErrorCode.ProviderNotConfigured,
                "云端鉴权 API 或受限 SSH 中继配置尚未设置。");
        }
        if (!_approvalStates.TryGetValue(device.DeviceId, out var approved) || !approved)
        {
            return new ConnectionIdentityResult(
                ConnectionIdentityState.RequestRequired, null, null, IdentityProviderErrorCode.ApprovalPending,
                "尚未通过云端读取到此设备的批准状态；不会尝试 SSH 或本地直连。");
        }

        try
        {
            var local = await _identityStore.LoadOrCreateAsync(cancellationToken).ConfigureAwait(false);
            if (!SameDevice(device, local.DeviceIdentity))
            {
                return new ConnectionIdentityResult(
                    ConnectionIdentityState.Failed, null, null, IdentityProviderErrorCode.AuthenticationFailed,
                    "本机持久身份与获批设备不一致。");
            }

            var profile = new SshConnectionProfile(
                server!.Host,
                server.Port,
                server.Username,
                "",
                null)
            {
                PrivateKeyIdentityId = device.DeviceId,
                PrivateKeyStreamProvider = local.OpenPrivateKeyStream,
                TrustedHostFingerprints = server.TrustedHostFingerprints.ToArray()
            };
            var identity = new ConnectionIdentity(
                device.DeviceId,
                server,
                profile,
                new ConnectionCredentialStatus(true, null, false));
            return new ConnectionIdentityResult(ConnectionIdentityState.Ready, identity, null, null, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            var failure = MapException(exception);
            return new ConnectionIdentityResult(
                ConnectionIdentityState.Failed, null, null, failure.Code, failure.Message);
        }
    }

    public async Task<ConnectionIdentityResult> RefreshAuthorizationAsync(
        DeviceIdentity device,
        string credentialId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_latestRequestIds.TryGetValue(device.DeviceId, out var requestId))
        {
            return new ConnectionIdentityResult(
                ConnectionIdentityState.RequestRequired, null, null, IdentityProviderErrorCode.ApprovalPending,
                "尚未读取此设备的云端审批记录。");
        }

        var status = await GetApprovalStatusAsync(requestId, cancellationToken).ConfigureAwait(false);
        if (!status.IsConfigured || !status.Succeeded || status.Value is null)
        {
            var state = status.ErrorCode switch
            {
                IdentityProviderErrorCode.AuthorizationRevoked => ConnectionIdentityState.Revoked,
                IdentityProviderErrorCode.RequestExpired or IdentityProviderErrorCode.RequestNotFound => ConnectionIdentityState.Expired,
                IdentityProviderErrorCode.ProviderNotConfigured => ConnectionIdentityState.NotConfigured,
                _ => ConnectionIdentityState.Failed
            };
            return new ConnectionIdentityResult(state, null, null, status.ErrorCode, status.UserMessage);
        }

        var request = status.Value;
        var stateFromStatus = request.Status switch
        {
            DeviceApprovalStatus.Pending => ConnectionIdentityState.Pending,
            DeviceApprovalStatus.Approved => ConnectionIdentityState.Ready,
            DeviceApprovalStatus.Rejected => ConnectionIdentityState.Rejected,
            DeviceApprovalStatus.Expired => ConnectionIdentityState.Expired,
            DeviceApprovalStatus.Revoked => ConnectionIdentityState.Revoked,
            _ => ConnectionIdentityState.Failed
        };
        if (stateFromStatus != ConnectionIdentityState.Ready)
            return new ConnectionIdentityResult(stateFromStatus, null, request, request.ErrorCode, request.UserMessage);

        var acquired = await AcquireConnectionIdentityAsync(device, cancellationToken).ConfigureAwait(false);
        return acquired with { AccessRequest = request };
    }

    public void Dispose()
    {
        if (_ownsHttpClient) _httpClient.Dispose();
    }

    private async Task<T> SendSignedJsonAsync<T>(
        DeviceIdentity device,
        HttpMethod method,
        string requestTarget,
        byte[] rawBody,
        CancellationToken cancellationToken)
    {
        if (rawBody.Length > MaximumBodyBytes)
            throw new AuthorizationClientException(
                IdentityProviderErrorCode.InvalidServerResponse,
                "鉴权请求超过允许大小。");
        if (!TryGetApiBaseUri(out var baseUri))
            throw new AuthorizationClientException(IdentityProviderErrorCode.ProviderNotConfigured,
                "云端鉴权 HTTPS 地址尚未配置或无效。");

        using var operationTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        operationTimeout.CancelAfter(TimeSpan.FromSeconds(25));
        for (var attempt = 0; attempt < MaximumAttempts; attempt++)
        {
            try
            {
                var challenge = await CreateDeviceChallengeAsync(device, baseUri!, operationTimeout.Token).ConfigureAwait(false);
                if (challenge.ExpiresUtc <= _timeProvider.GetUtcNow().AddSeconds(1))
                    throw new AuthorizationClientException(IdentityProviderErrorCode.RequestExpired,
                        "云端签名挑战已过期，请重试。", retryable: true);

                var local = await EnsureLocalIdentityMatchesAsync(device, operationTimeout.Token).ConfigureAwait(false);
                using var signingKey = OpenSigningKey(local);
                var timestamp = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
                var envelope = DeviceRequestSigner.Sign(
                    signingKey,
                    device.DeviceId,
                    challenge.ChallengeId,
                    challenge.Nonce,
                    timestamp,
                    method.Method,
                    requestTarget,
                    rawBody);
                using var request = new HttpRequestMessage(method, new Uri(baseUri!, requestTarget.TrimStart('/')));
                if (method != HttpMethod.Get)
                {
                    request.Content = new ByteArrayContent(rawBody);
                    request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                }
                request.Headers.TryAddWithoutValidation("X-MoDi-Key-Id", envelope.KeyId);
                request.Headers.TryAddWithoutValidation("X-MoDi-Challenge-Id", envelope.ChallengeId);
                request.Headers.TryAddWithoutValidation("X-MoDi-Nonce", envelope.Nonce);
                request.Headers.TryAddWithoutValidation(
                    "X-MoDi-Timestamp", envelope.UnixTimestamp.ToString(CultureInfo.InvariantCulture));
                request.Headers.TryAddWithoutValidation("X-MoDi-Signature", envelope.SignatureBase64);

                using var requestTimeout = CreateRequestTimeout(operationTimeout.Token);
                using var response = await _httpClient.SendAsync(
                    request, HttpCompletionOption.ResponseHeadersRead, requestTimeout.Token).ConfigureAwait(false);
                var responseBody = await ReadBoundedBodyAsync(response, requestTimeout.Token).ConfigureAwait(false);
                if (IsTransientStatus(response.StatusCode))
                {
                    CryptographicOperations.ZeroMemory(responseBody);
                    if (attempt + 1 < MaximumAttempts)
                    {
                        await Task.Delay(RetryDelays[attempt], cancellationToken).ConfigureAwait(false);
                        continue;
                    }
                    throw new AuthorizationClientException(
                        IdentityProviderErrorCode.NetworkUnavailable,
                        "云端鉴权服务暂时不可用；没有切换到本地直连。 ");
                }

                if (!response.IsSuccessStatusCode)
                {
                    var failure = CreateHttpFailure(response.StatusCode, responseBody);
                    CryptographicOperations.ZeroMemory(responseBody);
                    throw failure;
                }

                try
                {
                    return JsonSerializer.Deserialize<T>(responseBody, JsonOptions)
                        ?? throw new AuthorizationClientException(
                            IdentityProviderErrorCode.InvalidServerResponse,
                            "云端鉴权响应为空或格式无效。");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(responseBody);
                }
            }
            catch (AuthorizationClientException exception) when (exception.Retryable && attempt + 1 < MaximumAttempts)
            {
                await Task.Delay(RetryDelays[attempt], cancellationToken).ConfigureAwait(false);
            }
            catch (HttpRequestException) when (attempt + 1 < MaximumAttempts)
            {
                await Task.Delay(RetryDelays[attempt], cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException) when (operationTimeout.IsCancellationRequested)
            {
                throw new AuthorizationClientException(
                    IdentityProviderErrorCode.NetworkUnavailable,
                    "云端鉴权操作超时；没有切换到本地直连。");
            }
            catch (OperationCanceledException) when (attempt + 1 < MaximumAttempts)
            {
                await Task.Delay(RetryDelays[attempt], cancellationToken).ConfigureAwait(false);
            }
            catch (HttpRequestException exception)
            {
                throw new AuthorizationClientException(
                    IdentityProviderErrorCode.NetworkUnavailable,
                    "无法连接云端鉴权服务；没有切换到本地直连。 ",
                    innerException: exception);
            }
            catch (OperationCanceledException exception)
            {
                throw new AuthorizationClientException(
                    IdentityProviderErrorCode.NetworkUnavailable,
                    "云端鉴权请求超时；没有切换到本地直连。 ",
                    innerException: exception);
            }
            catch (JsonException exception)
            {
                throw new AuthorizationClientException(
                    IdentityProviderErrorCode.InvalidServerResponse,
                    "云端鉴权响应格式无效。 ",
                    innerException: exception);
            }
        }

        throw new AuthorizationClientException(
            IdentityProviderErrorCode.NetworkUnavailable,
            "云端鉴权服务暂时不可用；没有切换到本地直连。");
    }

    private async Task<DeviceChallengeDto> CreateDeviceChallengeAsync(
        DeviceIdentity device,
        Uri baseUri,
        CancellationToken cancellationToken)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(
            new DeviceChallengeCommandDto(device.DeviceId, device.PublicKeyFingerprint), JsonOptions);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(baseUri, "v1/device-challenges"))
            {
                Content = new ByteArrayContent(body)
            };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            using var requestTimeout = CreateRequestTimeout(cancellationToken);
            using var response = await _httpClient.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, requestTimeout.Token).ConfigureAwait(false);
            var responseBody = await ReadBoundedBodyAsync(response, requestTimeout.Token).ConfigureAwait(false);
            if (IsTransientStatus(response.StatusCode))
            {
                CryptographicOperations.ZeroMemory(responseBody);
                throw new AuthorizationClientException(
                    IdentityProviderErrorCode.NetworkUnavailable,
                    "云端鉴权服务暂时不可用。 ", retryable: true);
            }
            if (!response.IsSuccessStatusCode)
            {
                var error = CreateHttpFailure(response.StatusCode, responseBody);
                CryptographicOperations.ZeroMemory(responseBody);
                throw error;
            }

            try
            {
                var challenge = JsonSerializer.Deserialize<DeviceChallengeDto>(responseBody, JsonOptions)
                    ?? throw new AuthorizationClientException(
                        IdentityProviderErrorCode.InvalidServerResponse,
                        "云端签名挑战响应无效。");
                if (!IsValidToken(challenge.ChallengeId) || !IsValidToken(challenge.Nonce))
                    throw new AuthorizationClientException(
                        IdentityProviderErrorCode.InvalidServerResponse,
                        "云端签名挑战响应无效。");
                return challenge;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(responseBody);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
        }
    }

    private static CancellationTokenSource CreateRequestTimeout(CancellationToken cancellationToken)
    {
        var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(RequestTimeout);
        return timeout;
    }

    private static async Task<byte[]> ReadBoundedBodyAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is > MaximumBodyBytes)
            throw new AuthorizationClientException(
                IdentityProviderErrorCode.InvalidServerResponse,
                "云端鉴权响应超过允许大小。");

        await using var input = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            if (output.Length + read > MaximumBodyBytes)
                throw new AuthorizationClientException(
                    IdentityProviderErrorCode.InvalidServerResponse,
                    "云端鉴权响应超过允许大小。");
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private async Task<LocalDeviceIdentity> EnsureLocalIdentityMatchesAsync(
        DeviceIdentity device,
        CancellationToken cancellationToken)
    {
        var local = await _identityStore.LoadOrCreateAsync(cancellationToken).ConfigureAwait(false);
        if (!SameDevice(device, local.DeviceIdentity))
        {
            throw new AuthorizationClientException(
                IdentityProviderErrorCode.AuthenticationFailed,
                "请求设备身份与本机保存的密钥不一致。");
        }
        return local;
    }

    private static ECDsa OpenSigningKey(LocalDeviceIdentity identity)
    {
        using var stream = identity.OpenPrivateKeyStream();
        var bytes = new byte[4096];
        var length = 0;
        try
        {
            while (length < bytes.Length)
            {
                var read = stream.Read(bytes, length, bytes.Length - length);
                if (read == 0) break;
                length += read;
            }
            if (length == bytes.Length && stream.ReadByte() != -1)
                throw new CryptographicException("Stored device key exceeds the supported size.");

            var characters = new char[Encoding.UTF8.GetCharCount(bytes.AsSpan(0, length))];
            try
            {
                _ = Encoding.UTF8.GetChars(bytes.AsSpan(0, length), characters);
                var key = ECDsa.Create();
                try
                {
                    key.ImportFromPem(characters);
                    if (key.KeySize != 256 ||
                        !StringComparer.Ordinal.Equals(key.ExportParameters(false).Curve.Oid.Value, "1.2.840.10045.3.1.7"))
                    {
                        throw new CryptographicException("Stored device key is not P-256.");
                    }
                    return key;
                }
                catch
                {
                    key.Dispose();
                    throw;
                }
            }
            finally
            {
                Array.Clear(characters);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private bool TryGetApiBaseUri(out Uri? baseUri)
    {
        if (_options.TryGetApiBaseUri(out baseUri)) return true;
        baseUri = null;
        return false;
    }

    private static DeviceAccessRequest ConvertAccessRequest(AccessRequestDto response)
    {
        if (!IsValidRequestId(response.RequestId) || !DeviceIdFactory.IsValid(response.DeviceId) ||
            !DateTimeOffset.TryParse(response.CreatedUtc, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var created) ||
            !DateTimeOffset.TryParse(response.ExpiresUtc, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var expires) ||
            !Enum.TryParse<DeviceApprovalStatus>(response.Status, ignoreCase: true, out var status) ||
            !Enum.IsDefined(status))
        {
            throw new AuthorizationClientException(
                IdentityProviderErrorCode.InvalidServerResponse,
                "云端审批状态响应无效。");
        }

        return new DeviceAccessRequest(
            response.RequestId,
            response.DeviceId,
            created,
            expires,
            status,
            MapServiceErrorCode(response.ErrorCode),
            SafeRequestMessage(status));
    }

    private static AuthorizationClientException CreateHttpFailure(HttpStatusCode statusCode, byte[] responseBody)
    {
        string? serviceCode = null;
        try
        {
            using var document = JsonDocument.Parse(responseBody);
            if (document.RootElement.ValueKind == JsonValueKind.Object &&
                document.RootElement.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String)
                serviceCode = code.GetString();
        }
        catch (JsonException)
        {
        }

        var error = MapServiceErrorCode(serviceCode);
        var retryable = IsTransientStatus(statusCode);
        return new AuthorizationClientException(
            error ?? (retryable ? IdentityProviderErrorCode.NetworkUnavailable : IdentityProviderErrorCode.Unknown),
            SafeErrorMessage(error, retryable),
            retryable);
    }

    private static IdentityProviderErrorCode? MapServiceErrorCode(string? code) => code?.ToLowerInvariant() switch
    {
        "devicenotregistered" => IdentityProviderErrorCode.DeviceNotRegistered,
        "devicerevoked" => IdentityProviderErrorCode.AuthorizationRevoked,
        "requestexpired" or "challengeexpired" => IdentityProviderErrorCode.RequestExpired,
        "requestnotfound" => IdentityProviderErrorCode.RequestNotFound,
        "invalidsignature" => IdentityProviderErrorCode.AuthenticationFailed,
        _ => null
    };

    private static string SafeErrorMessage(IdentityProviderErrorCode? code, bool retryable) => code switch
    {
        IdentityProviderErrorCode.AuthorizationRevoked => "此设备授权已被管理员撤销。 ",
        IdentityProviderErrorCode.DeviceNotRegistered => "此设备尚未在云端登记。 ",
        IdentityProviderErrorCode.RequestNotFound => "设备申请不存在或已失效。 ",
        IdentityProviderErrorCode.RequestExpired => "设备申请或签名挑战已过期，请重试。 ",
        IdentityProviderErrorCode.AuthenticationFailed => "云端无法验证本机设备密钥。 ",
        _ when retryable => "云端鉴权服务暂时不可用；没有切换到本地直连。 ",
        _ => "云端鉴权请求未成功。 "
    };

    private static string SafeRequestMessage(DeviceApprovalStatus status) => status switch
    {
        DeviceApprovalStatus.Pending => "设备申请正在等待管理员审批。 ",
        DeviceApprovalStatus.Approved => "此设备已获准连接下载中继。 ",
        DeviceApprovalStatus.Rejected => "设备申请已被管理员拒绝。 ",
        DeviceApprovalStatus.Expired => "设备申请已过期，可以重新申请。 ",
        DeviceApprovalStatus.Revoked => "此设备授权已被管理员撤销。 ",
        _ => "无法识别云端审批状态。 "
    };

    private static IdentityProviderOperationResult<T> ConfiguredSuccess<T>(T value) =>
        new(true, true, value, null, null);

    private static IdentityProviderOperationResult<T> NotConfigured<T>(string message) =>
        new(false, false, default, IdentityProviderErrorCode.ProviderNotConfigured, message);

    private static IdentityProviderOperationResult<T> Failure<T>(Exception exception)
    {
        var failure = MapException(exception);
        return new IdentityProviderOperationResult<T>(true, false, default, failure.Code, failure.Message);
    }

    private static (IdentityProviderErrorCode Code, string Message) MapException(Exception exception) => exception switch
    {
        AuthorizationClientException api => (api.Code, api.Message),
        DeviceIdentityStoreException => (IdentityProviderErrorCode.AuthenticationFailed, "本机设备密钥不可用；未重新生成身份。 "),
        HttpRequestException => (IdentityProviderErrorCode.NetworkUnavailable, "无法连接云端鉴权服务；没有切换到本地直连。 "),
        JsonException => (IdentityProviderErrorCode.InvalidServerResponse, "云端鉴权响应格式无效。 "),
        CryptographicException => (IdentityProviderErrorCode.AuthenticationFailed, "本机设备密钥无法完成签名。 "),
        _ => (IdentityProviderErrorCode.Unknown, "云端鉴权操作未完成。 ")
    };

    private static bool SameDevice(DeviceIdentity left, DeviceIdentity right) =>
        StringComparer.Ordinal.Equals(left.DeviceId, right.DeviceId) &&
        StringComparer.Ordinal.Equals(left.PublicKeyFingerprint, right.PublicKeyFingerprint) &&
        StringComparer.Ordinal.Equals(left.PublicKey, right.PublicKey);

    private static bool IsTransientStatus(HttpStatusCode statusCode) =>
        statusCode is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests || (int)statusCode >= 500;

    private static bool IsValidRequestId(string? requestId) =>
        requestId is { Length: 32 } && requestId.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsValidToken(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 128 &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    private sealed record DeviceChallengeCommandDto(string DeviceId, string PublicKeyFingerprint);
    private sealed record DeviceChallengeDto(string ChallengeId, string Nonce, DateTimeOffset ExpiresUtc);
    private sealed record RegisterDeviceCommandDto(string DeviceId, string DisplayName, string OpenSshPublicKey);
    private sealed record RegisteredDeviceDto(
        string DeviceId,
        string DisplayName,
        string OpenSshPublicKey,
        string PublicKeyFingerprint,
        DateTimeOffset CreatedUtc,
        string Status);
    private sealed record RequestAccessCommandDto(string IdempotencyKey);
    private sealed record AccessRequestDto(
        string RequestId,
        string DeviceId,
        string CreatedUtc,
        string ExpiresUtc,
        string Status,
        string? ErrorCode,
        string? UserMessage);

    private sealed class AuthorizationClientException(
        IdentityProviderErrorCode code,
        string message,
        bool retryable = false,
        Exception? innerException = null)
        : Exception(message, innerException)
    {
        public IdentityProviderErrorCode Code { get; } = code;
        public bool Retryable { get; } = retryable;
    }
}
