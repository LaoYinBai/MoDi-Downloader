using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Transport;

public sealed partial class DownloadManager : IAsyncDisposable
{
    public const int MaximumActiveTasks = 4;
    public const int MaximumGlobalConnections = 64;
    public const int MaximumRetries = 5;
    public const int BufferSize = 64 * 1024;
    public const long DefaultChunkSizeBytes = 1_048_576;

    private readonly ITunneledHttpClientPool _tunnels;
    private readonly JsonDownloadManifestStore _manifestStore;
    private readonly SemaphoreSlim _activeTaskSlots;
    private readonly SemaphoreSlim _globalConnectionSlots;
    private readonly int _maximumGlobalConnections;
    private readonly ConcurrentDictionary<Guid, DownloadJobState> _jobs = new();
    private int _activeConnections;
    private int _disposed;

    public DownloadManager(
        ITunneledHttpClientPool tunnels,
        JsonDownloadManifestStore manifestStore,
        int maximumActiveTasks = MaximumActiveTasks,
        int maximumGlobalConnections = MaximumGlobalConnections)
    {
        ArgumentNullException.ThrowIfNull(tunnels);
        ArgumentNullException.ThrowIfNull(manifestStore);
        if (maximumActiveTasks is < 1 or > 16)
            throw new ArgumentOutOfRangeException(nameof(maximumActiveTasks));
        if (maximumGlobalConnections is < 1 or > MaximumGlobalConnections)
            throw new ArgumentOutOfRangeException(nameof(maximumGlobalConnections));

        _tunnels = tunnels;
        _manifestStore = manifestStore;
        _maximumGlobalConnections = maximumGlobalConnections;
        _activeTaskSlots = new SemaphoreSlim(maximumActiveTasks, maximumActiveTasks);
        _globalConnectionSlots = new SemaphoreSlim(maximumGlobalConnections, maximumGlobalConnections);
    }

    public event EventHandler<DownloadTaskSnapshot>? SnapshotChanged;

    public int ActiveConnectionCount => Volatile.Read(ref _activeConnections);

    public IReadOnlyList<DownloadTaskSnapshot> GetSnapshots() =>
        _jobs.Values.Select(job => job.CreateSnapshot()).OrderBy(snapshot => snapshot.FileName).ToArray();

    public DownloadTaskSnapshot GetSnapshot(Guid id) =>
        _jobs.TryGetValue(id, out var job) ? job.CreateSnapshot() : throw new KeyNotFoundException();

    public Task<Guid> AddAsync(DownloadRequest request)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(request);
        if (!UrlSafety.TryValidateDownloadUri(request.SourceUri.AbsoluteUri, out var safeUri))
            throw new ArgumentException("Only credential-free HTTP and HTTPS URLs are supported.", nameof(request));
        if (request.InitialConcurrency is < 1 or > AdaptiveConcurrencyController.MaximumConcurrency)
            throw new ArgumentOutOfRangeException(nameof(request));
        if (request.ChunkSizeBytes is < 64 * 1024 or > 16 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(request));
        if (string.IsNullOrWhiteSpace(request.SaveDirectory) || !Path.IsPathFullyQualified(request.SaveDirectory))
            throw new ArgumentException("Choose a local save directory.", nameof(request));

        var normalizedRequest = request with
        {
            SourceUri = safeUri!,
            SaveDirectory = Path.GetFullPath(request.SaveDirectory)
        };
        Directory.CreateDirectory(normalizedRequest.SaveDirectory);

        var job = new DownloadJobState(normalizedRequest);
        if (!_jobs.TryAdd(job.Id, job))
            throw new InvalidOperationException("Could not create the download task.");

        Publish(job, force: true);
        StartRunner(job);
        return Task.FromResult(job.Id);
    }

    public async Task<int> RestoreAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var manifests = await _manifestStore.LoadAllAsync(cancellationToken).ConfigureAwait(false);
        var restored = 0;
        foreach (var manifest in manifests)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var job = new DownloadJobState(manifest);
            if (manifest.Completed)
            {
                job.SetStatus(File.Exists(manifest.TargetPath)
                    ? DownloadTaskStatus.Completed
                    : DownloadTaskStatus.Failed,
                    File.Exists(manifest.TargetPath) ? null : "已完成文件不存在。");
            }
            else if (manifest.CompletedChunkIndexes.Count > 0 && !File.Exists(manifest.PartialPath))
            {
                job.SetStatus(DownloadTaskStatus.Failed, "续传临时文件不存在，无法安全恢复。");
            }
            else
            {
                job.SetStatus(DownloadTaskStatus.Paused);
            }

            if (_jobs.TryAdd(job.Id, job))
            {
                restored++;
                Publish(job, force: true);
            }
        }

        return restored;
    }

    public async Task ResumeAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var job = GetJob(id);
        if (job.CreateSnapshot().Status is DownloadTaskStatus.Completed or DownloadTaskStatus.Cancelled)
            return;
        if (job.CreateSnapshot().Status == DownloadTaskStatus.ResourceChanged)
            throw new InvalidOperationException("服务器资源已变化。请选择从头重新下载。 ");

        await WaitForPreviousRunAsync(job).ConfigureAwait(false);
        job.PauseRequested = false;
        job.CancelRequested = false;
        job.SetStatus(DownloadTaskStatus.Waiting);
        Publish(job, force: true);
        StartRunner(job, cancellationToken);
    }

    public async Task RestartAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var job = GetJob(id);
        await StopRunnerAsync(job, cancel: true, pause: false).ConfigureAwait(false);
        var manifest = job.Manifest;
        if (manifest is not null)
        {
            TryDeletePartial(manifest.PartialPath);
            await _manifestStore.DeleteAsync(id, cancellationToken).ConfigureAwait(false);
        }

        job.ResetForRestart();
        Publish(job, force: true);
        StartRunner(job, cancellationToken);
    }

    public async Task PauseAsync(Guid id)
    {
        var job = GetJob(id);
        await StopRunnerAsync(job, cancel: false, pause: true).ConfigureAwait(false);
    }

    public async Task CancelAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var job = GetJob(id);
        if (job.CreateSnapshot().Status == DownloadTaskStatus.Completed)
            return;

        await StopRunnerAsync(job, cancel: true, pause: false).ConfigureAwait(false);
        var manifest = job.Manifest;
        if (manifest is not null)
        {
            TryDeletePartial(manifest.PartialPath);
            await _manifestStore.DeleteAsync(id, cancellationToken).ConfigureAwait(false);
        }
        job.SetStatus(DownloadTaskStatus.Cancelled);
        Publish(job, force: true);
    }

    public async Task PauseAllAsync()
    {
        var active = _jobs.Values
            .Where(job => job.CreateSnapshot().Status is DownloadTaskStatus.Waiting or DownloadTaskStatus.Inspecting or
                DownloadTaskStatus.Connecting or DownloadTaskStatus.Downloading or DownloadTaskStatus.Reconnecting)
            .Select(job => PauseAsync(job.Id));
        await Task.WhenAll(active).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        await PauseAllAsync().ConfigureAwait(false);
        _activeTaskSlots.Dispose();
        _globalConnectionSlots.Dispose();
    }

    private async Task RunJobAsync(DownloadJobState job, CancellationToken cancellationToken)
    {
        var taskSlotTaken = false;
        try
        {
            await _activeTaskSlots.WaitAsync(cancellationToken).ConfigureAwait(false);
            taskSlotTaken = true;
            job.SetStatus(DownloadTaskStatus.Inspecting);
            Publish(job, force: true);

            var probe = await ProbeWithRetryAsync(job, cancellationToken).ConfigureAwait(false);
            await ConfigureManifestAsync(job, probe, cancellationToken).ConfigureAwait(false);
            var manifest = job.Manifest ?? throw new InvalidOperationException("Download manifest was not initialized.");
            job.ResetThroughputWindow();

            if (job.SupportsRanges && manifest.Resource.TotalLength > 0)
                await ExecuteRangeDownloadAsync(job, cancellationToken).ConfigureAwait(false);
            else
                await ExecuteSingleStreamDownloadAsync(job, cancellationToken).ConfigureAwait(false);

            await FinalizeDownloadAsync(job, cancellationToken).ConfigureAwait(false);
        }
        catch (ResourceChangedException exception)
        {
            job.SetStatus(DownloadTaskStatus.ResourceChanged, exception.Message);
        }
        catch (OperationCanceledException) when (job.CancelRequested)
        {
            job.SetStatus(DownloadTaskStatus.Cancelled);
        }
        catch (OperationCanceledException) when (job.PauseRequested)
        {
            job.SetStatus(DownloadTaskStatus.Paused);
            await PersistManifestBestEffortAsync(job).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            job.SetStatus(DownloadTaskStatus.Paused);
            await PersistManifestBestEffortAsync(job).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            job.SetStatus(DownloadTaskStatus.Failed, FriendlyError(exception));
            await PersistManifestBestEffortAsync(job).ConfigureAwait(false);
        }
        finally
        {
            if (taskSlotTaken)
                _activeTaskSlots.Release();
            Publish(job, force: true);
        }
    }

    private async Task<ProbeResult> ProbeWithRetryAsync(DownloadJobState job, CancellationToken cancellationToken)
    {
        for (var attempt = 0; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await ProbeAsync(job.Request.SourceUri, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception exception) when (ShouldRetry(exception) && attempt < MaximumRetries - 1)
            {
                job.RecordRequestError();
                job.SetStatus(_tunnels.IsConnected ? DownloadTaskStatus.Connecting : DownloadTaskStatus.Reconnecting);
                Publish(job, force: true);
                await WaitOrBackoffAsync(attempt, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task<ProbeResult> ProbeAsync(Uri sourceUri, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, sourceUri);
        request.Headers.Range = new RangeHeaderValue(0, 0);
        request.Headers.AcceptEncoding.ParseAdd("identity");

        using var responseLease = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        var response = responseLease.Response;
        var finalUri = response.RequestMessage?.RequestUri ?? sourceUri;
        var contentRange = response.Content.Headers.ContentRange;
        var supportsRanges = response.StatusCode == HttpStatusCode.PartialContent &&
            contentRange?.From == 0 &&
            contentRange.To == 0 &&
            contentRange.Length is > 0;

        if (response.StatusCode is not (HttpStatusCode.OK or HttpStatusCode.PartialContent))
            response.EnsureSuccessStatusCode();

        var totalLength = supportsRanges
            ? contentRange!.Length!.Value
            : response.Content.Headers.ContentLength ?? 0;
        var identity = new ResourceIdentity(
            totalLength,
            supportsRanges,
            response.Headers.ETag?.ToString(),
            response.Content.Headers.LastModified)
        {
            ExpectedSha256 = TryGetExpectedSha256(response)
        };

        var fileName = GetSuggestedFileName(response, finalUri);
        return new ProbeResult(finalUri, fileName, identity);
    }

    private async Task ConfigureManifestAsync(
        DownloadJobState job,
        ProbeResult probe,
        CancellationToken cancellationToken)
    {
        var existing = job.Manifest;
        if (existing is null)
        {
            var targetPath = FindUniqueTargetPath(job.Request.SaveDirectory, probe.FileName);
            var manifest = new DownloadManifest
            {
                Id = job.Id,
                SourceUrl = job.Request.SourceUri.AbsoluteUri,
                FinalUrl = probe.FinalUri.AbsoluteUri,
                TargetPath = targetPath,
                PartialPath = targetPath + ".modi.part",
                Resource = probe.Identity,
                ChunkSizeBytes = job.Request.ChunkSizeBytes,
                RequestedConcurrency = job.Request.InitialConcurrency,
                AutoTuneConcurrency = job.Request.AutoTuneConcurrency
            };
            job.SetManifest(manifest);
        }
        else if (existing.Resource.AcceptsRanges)
        {
            if (!ResumeValidator.CanResume(existing.Resource, probe.Identity))
                throw new ResourceChangedException("服务器文件标识已变化，已停止续传以避免拼接损坏文件。");

            existing.Resource = probe.Identity;
            existing.FinalUrl = probe.FinalUri.AbsoluteUri;
            job.SetManifest(existing, restored: true);
        }
        else
        {
            existing.Resource = probe.Identity;
            existing.FinalUrl = probe.FinalUri.AbsoluteUri;
            existing.StreamBytesWritten = 0;
            existing.CompletedChunkIndexes.Clear();
            TryDeletePartial(existing.PartialPath);
            job.SetManifest(existing);
        }

        await SaveManifestAsync(job, cancellationToken, force: true).ConfigureAwait(false);
    }

    private async Task<ResponseLease> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await _globalConnectionSlots.WaitAsync(cancellationToken).ConfigureAwait(false);
        Interlocked.Increment(ref _activeConnections);
        var globalLease = new GlobalConnectionLease(_globalConnectionSlots, () => Interlocked.Decrement(ref _activeConnections));

        ITunneledHttpClientLease tunnelLease;
        try
        {
            tunnelLease = _tunnels.AcquireHttpClient();
        }
        catch
        {
            globalLease.Dispose();
            throw;
        }

        var timeoutToken = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutToken.CancelAfter(TimeSpan.FromMinutes(2));
        try
        {
            var response = await tunnelLease.HttpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                timeoutToken.Token).ConfigureAwait(false);
            return new ResponseLease(response, tunnelLease, globalLease, timeoutToken);
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            timeoutToken.Dispose();
            tunnelLease.Dispose();
            globalLease.Dispose();
            throw new TimeoutException("HTTP request exceeded the total execution timeout.", exception);
        }
        catch
        {
            timeoutToken.Dispose();
            tunnelLease.Dispose();
            globalLease.Dispose();
            throw;
        }
    }

    private async Task SaveManifestAsync(DownloadJobState job, CancellationToken cancellationToken, bool force = false)
    {
        var manifest = job.Manifest;
        if (manifest is null || !job.TryBeginManifestSave(force))
            return;

        await job.ManifestSaveGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            manifest.CompletedChunkIndexes = job.CompletedChunkIndexes().ToList();
            manifest.StreamBytesWritten = job.SupportsRanges ? 0 : job.GetReceivedBytes();
            manifest.RetryCount = job.RetryCount;
            manifest.RequestedConcurrency = job.CurrentConcurrency;
            await _manifestStore.SaveAsync(manifest, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            job.ManifestSaveGate.Release();
        }
    }

    private async Task PersistManifestBestEffortAsync(DownloadJobState job)
    {
        try
        {
            await SaveManifestAsync(job, CancellationToken.None, force: true).ConfigureAwait(false);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private void StartRunner(DownloadJobState job, CancellationToken externalCancellation = default)
    {
        var previous = job.RunCancellation;
        job.RunCancellation = CancellationTokenSource.CreateLinkedTokenSource(externalCancellation);
        previous?.Dispose();
        job.PauseRequested = false;
        job.CancelRequested = false;

        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        job.Runner = Task.Run(async () =>
        {
            await started.Task.ConfigureAwait(false);
            await RunJobAsync(job, job.RunCancellation.Token).ConfigureAwait(false);
        });
        started.SetResult();
    }

    private async Task StopRunnerAsync(DownloadJobState job, bool cancel, bool pause)
    {
        var runner = job.Runner;
        if (runner is null || runner.IsCompleted)
        {
            if (pause && job.CreateSnapshot().Status is not (DownloadTaskStatus.Completed or DownloadTaskStatus.Cancelled))
                job.SetStatus(DownloadTaskStatus.Paused);
            if (cancel)
                job.SetStatus(DownloadTaskStatus.Cancelled);
            Publish(job, force: true);
            return;
        }

        job.CancelRequested = cancel;
        job.PauseRequested = pause;
        if (pause)
            job.SetStatus(DownloadTaskStatus.Paused);
        if (cancel)
            job.SetStatus(DownloadTaskStatus.Cancelled);
        job.RunCancellation?.Cancel();
        Publish(job, force: true);

        try
        {
            await runner.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        if (pause && job.Manifest is not null)
            await PersistManifestBestEffortAsync(job).ConfigureAwait(false);
        job.RunCancellation?.Dispose();
        job.RunCancellation = null;
        job.Runner = null;
        if (cancel)
            job.SetStatus(DownloadTaskStatus.Cancelled);
        else if (pause)
            job.SetStatus(DownloadTaskStatus.Paused);
        Publish(job, force: true);
    }

    private async Task WaitForPreviousRunAsync(DownloadJobState job)
    {
        if (job.Runner is { } runner)
        {
            try
            {
                await runner.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }
        job.RunCancellation?.Dispose();
        job.RunCancellation = null;
        job.Runner = null;
    }

    private DownloadJobState GetJob(Guid id) =>
        _jobs.TryGetValue(id, out var job) ? job : throw new KeyNotFoundException("Download task not found.");

    private void Publish(DownloadJobState job, bool force)
    {
        if (force || job.ShouldPublish())
            SnapshotChanged?.Invoke(this, job.CreateSnapshot());
    }

    private static bool ShouldRetry(Exception exception)
    {
        if (exception is ResourceChangedException or OperationCanceledException)
            return false;
        if (exception is HttpRequestException { StatusCode: { } status } &&
            (int)status is >= 400 and < 500 &&
            status is not (HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests))
            return false;
        return exception is IOException or HttpRequestException or TunnelUnavailableException or TimeoutException;
    }

    private async Task WaitOrBackoffAsync(int attempt, CancellationToken cancellationToken)
    {
        if (!_tunnels.IsConnected)
        {
            await _tunnels.WaitUntilConnectedAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        var milliseconds = Math.Min(8_000, 500 * (1 << Math.Min(attempt, 4)));
        await Task.Delay(TimeSpan.FromMilliseconds(milliseconds), cancellationToken).ConfigureAwait(false);
    }

    private static string FriendlyError(Exception exception) => exception switch
    {
        TunnelUnavailableException => "SSH 隧道断开；任务已暂停，恢复连接后可继续。",
        ResourceChangedException changed => changed.Message,
        UnauthorizedAccessException => "本地保存目录无写入权限。",
        ArgumentOutOfRangeException => "资源过大，分片数量超过安全跟踪上限。",
        HttpRequestException { StatusCode: { } status } => $"服务器返回 HTTP {(int)status}，下载已停止。",
        Socks5ProtocolException => "云端 SSH 代理无法连接目标站点。",
        TimeoutException => "网络请求超时，正在按安全策略重试。",
        HttpRequestException => "HTTP 连接失败，已达到安全重试上限。",
        IOException => "网络或本地文件读写中断，已保留可恢复的分片。",
        _ => "下载失败。检查连接、保存目录和任务详情后重试。"
    };

    private static string FindUniqueTargetPath(string directory, string suggestedName)
    {
        var name = DownloadFileName.Sanitize(suggestedName);
        var extension = Path.GetExtension(name);
        var stem = Path.GetFileNameWithoutExtension(name);
        for (var suffix = 0; suffix < 10_000; suffix++)
        {
            var candidateName = suffix == 0 ? name : $"{stem} ({suffix}){extension}";
            var candidate = Path.Combine(directory, candidateName);
            if (!File.Exists(candidate) && !File.Exists(candidate + ".modi.part"))
                return candidate;
        }

        throw new IOException("无法为下载文件分配不覆盖现有文件的名称。");
    }

    private static string GetSuggestedFileName(HttpResponseMessage response, Uri finalUri)
    {
        var disposition = response.Content.Headers.ContentDisposition;
        var suggested = disposition?.FileNameStar ?? disposition?.FileName?.Trim('"');
        if (string.IsNullOrWhiteSpace(suggested))
        {
            var leaf = Path.GetFileName(finalUri.AbsolutePath);
            suggested = string.IsNullOrWhiteSpace(leaf) ? "download.bin" : Uri.UnescapeDataString(leaf);
        }

        return DownloadFileName.Sanitize(suggested);
    }

    private static string? TryGetExpectedSha256(HttpResponseMessage response)
    {
        foreach (var headerName in new[] { "Content-Digest", "Digest" })
        {
            IEnumerable<string>? values = null;
            if (!response.Headers.TryGetValues(headerName, out values) &&
                !response.Content.Headers.TryGetValues(headerName, out values))
                continue;

            foreach (var item in values.SelectMany(value => value.Split(',')))
            {
                var separator = item.IndexOf('=');
                if (separator < 0 || !item[..separator].Trim().Equals("sha-256", StringComparison.OrdinalIgnoreCase))
                    continue;

                var encoded = item[(separator + 1)..].Trim().Trim(':').Trim('"');
                try
                {
                    var bytes = Convert.FromBase64String(encoded);
                    if (bytes.Length == 32)
                        return Convert.ToBase64String(bytes);
                }
                catch (FormatException)
                {
                }
            }
        }

        return null;
    }

    private static void TryDeletePartial(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private sealed record ProbeResult(Uri FinalUri, string FileName, ResourceIdentity Identity);

    private sealed class ResourceChangedException(string message) : IOException(message);

    private sealed class GlobalConnectionLease(SemaphoreSlim gate, Action released) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;
            released();
            gate.Release();
        }
    }

    private sealed class ResponseLease(
        HttpResponseMessage response,
        ITunneledHttpClientLease tunnelLease,
        IDisposable globalLease,
        CancellationTokenSource timeoutToken) : IDisposable
    {
        public HttpResponseMessage Response { get; } = response;
        public CancellationToken OperationToken { get; } = timeoutToken.Token;

        public void Dispose()
        {
            Response.Dispose();
            timeoutToken.Dispose();
            tunnelLease.Dispose();
            globalLease.Dispose();
        }
    }
}
