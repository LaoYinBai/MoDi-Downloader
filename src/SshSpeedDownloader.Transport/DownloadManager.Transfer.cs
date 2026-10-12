using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Transport;

public sealed partial class DownloadManager
{
    private async Task ExecuteRangeDownloadAsync(DownloadJobState job, CancellationToken cancellationToken)
    {
        var manifest = job.Manifest ?? throw new InvalidOperationException("Download manifest was not initialized.");
        var rangeCount = RangePartition.Count(manifest.Resource.TotalLength, manifest.ChunkSizeBytes);
        job.SetRangeMetadata(manifest.Resource, rangeCount);
        var pending = new RangeWorkQueue(
            manifest.Resource.TotalLength,
            manifest.ChunkSizeBytes,
            job.CompletedChunkIndexes());
        using var file = File.OpenHandle(
            manifest.PartialPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.Read,
            FileOptions.Asynchronous | FileOptions.RandomAccess);
        RandomAccess.SetLength(file, manifest.Resource.TotalLength);

        var initialConcurrency = Math.Clamp(job.CurrentConcurrency, 1, _maximumGlobalConnections);
        var gate = new AsyncConcurrencyGate(initialConcurrency);
        job.ConcurrencyGate = gate;
        job.SetStatus(DownloadTaskStatus.Connecting);
        Publish(job, force: true);

        using var tuningCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var tuningTask = TuneRangeTransferAsync(job, pending, gate, tuningCancellation.Token);
        var workers = Enumerable.Range(0, MaximumGlobalConnections)
            .Select(_ => RangeWorkerAsync(job, pending, gate, file, cancellationToken))
            .ToArray();

        try
        {
            await Task.WhenAll(workers).ConfigureAwait(false);
        }
        finally
        {
            tuningCancellation.Cancel();
            try
            {
                await tuningTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        RandomAccess.FlushToDisk(file);
        if (job.CompletedChunkCount != rangeCount)
            throw new IOException("下载分片未全部完成，临时文件已保留。 ");
    }

    private async Task RangeWorkerAsync(
        DownloadJobState job,
        RangeWorkQueue pending,
        AsyncConcurrencyGate gate,
        SafeFileHandle file,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            using var concurrencyLease = await gate.AcquireAsync(cancellationToken).ConfigureAwait(false);
            if (!pending.TryTake(out var range))
                return;

            await DownloadChunkWithRetryAsync(job, range, file, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task DownloadChunkWithRetryAsync(
        DownloadJobState job,
        DownloadRange range,
        SafeFileHandle file,
        CancellationToken cancellationToken)
    {
        Exception? lastException = null;
        for (var attempt = 0; attempt < MaximumRetries; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            job.BeginChunk(range);
            job.BeginConnection();
            var started = Stopwatch.GetTimestamp();
            try
            {
                job.SetStatus(_tunnels.IsConnected ? DownloadTaskStatus.Downloading : DownloadTaskStatus.Reconnecting);
                Publish(job, force: false);

                using var request = new HttpRequestMessage(HttpMethod.Get, job.Request.SourceUri);
                request.Headers.Range = new RangeHeaderValue(range.Offset, range.EndExclusive - 1);
                request.Headers.AcceptEncoding.ParseAdd("identity");
                ApplyIfRange(request, job.Manifest?.Resource);

                using var responseLease = await SendAsync(request, cancellationToken).ConfigureAwait(false);
                var responseLatencyMilliseconds = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                var response = responseLease.Response;
                if (response.StatusCode == HttpStatusCode.OK)
                    throw new ResourceChangedException("Range 請求返回完整文件，已停止以避免重复拼接。 ");
                response.EnsureSuccessStatusCode();
                ValidateRangeResponse(response, range, job.Manifest?.Resource);

                var expectedLength = range.Length;
                if (response.Content.Headers.ContentLength is { } contentLength && contentLength != expectedLength)
                    throw new ResourceChangedException("分片响应长度与请求范围不一致。 ");

                await using var input = await response.Content.ReadAsStreamAsync(responseLease.OperationToken)
                    .ConfigureAwait(false);
                var buffer = new byte[BufferSize];
                long written = 0;
                while (written < expectedLength)
                {
                    var readLimit = (int)Math.Min(buffer.Length, expectedLength - written);
                    var read = await input.ReadAsync(buffer.AsMemory(0, readLimit), responseLease.OperationToken)
                        .ConfigureAwait(false);
                    if (read == 0)
                        throw new IOException("分片响应提前结束。 ");

                    await RandomAccess.WriteAsync(
                        file,
                        buffer.AsMemory(0, read),
                        checked(range.Offset + written),
                        responseLease.OperationToken).ConfigureAwait(false);
                    written += read;
                    job.RecordBytes(range.Index, read);
                    Publish(job, force: false);
                }

                if (await input.ReadAsync(buffer.AsMemory(0, 1), responseLease.OperationToken).ConfigureAwait(false) != 0)
                    throw new ResourceChangedException("分片响应超过请求范围长度。 ");

                RandomAccess.FlushToDisk(file);
                job.CompleteChunk(range);
                job.RecordRequestSuccess(responseLatencyMilliseconds);
                await SaveManifestAsync(job, cancellationToken).ConfigureAwait(false);
                Publish(job, force: false);
                return;
            }
            catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
            {
                lastException = new TimeoutException("分片下载超时。 ", exception);
                job.RecordRequestError();
                job.IncrementChunkRetry(range.Index);
                job.SetStatus(_tunnels.IsConnected ? DownloadTaskStatus.Downloading : DownloadTaskStatus.Reconnecting);
                Publish(job, force: true);
                if (attempt + 1 >= MaximumRetries)
                    break;
                await WaitOrBackoffAsync(attempt, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (ResourceChangedException)
            {
                throw;
            }
            catch (Exception exception) when (ShouldRetry(exception))
            {
                lastException = exception;
                job.RecordRequestError();
                job.IncrementChunkRetry(range.Index);
                job.SetStatus(_tunnels.IsConnected ? DownloadTaskStatus.Downloading : DownloadTaskStatus.Reconnecting);
                Publish(job, force: true);
                if (attempt + 1 >= MaximumRetries)
                    break;
                await WaitOrBackoffAsync(attempt, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                job.EndConnection();
            }
        }

        throw lastException ?? new IOException("分片下载失败。 ");
    }

    private async Task ExecuteSingleStreamDownloadAsync(DownloadJobState job, CancellationToken cancellationToken)
    {
        var manifest = job.Manifest ?? throw new InvalidOperationException("Download manifest was not initialized.");
        job.SetConcurrency(1);
        job.ResetStreamBytes();
        job.SetStatus(DownloadTaskStatus.Connecting);
        Publish(job, force: true);

        Exception? lastException = null;
        for (var attempt = 0; attempt < MaximumRetries; attempt++)
        {
            job.ResetStreamBytes();
            job.BeginConnection();
            var started = Stopwatch.GetTimestamp();
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, job.Request.SourceUri);
                request.Headers.AcceptEncoding.ParseAdd("identity");
                using var responseLease = await SendAsync(request, cancellationToken).ConfigureAwait(false);
                var responseLatencyMilliseconds = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                if (responseLease.Response.StatusCode != HttpStatusCode.OK)
                    responseLease.Response.EnsureSuccessStatusCode();
                if (responseLease.Response.StatusCode != HttpStatusCode.OK)
                    throw new IOException("服务器未提供可用的单连接响应。 ");

                await using var input = await responseLease.Response.Content.ReadAsStreamAsync(responseLease.OperationToken)
                    .ConfigureAwait(false);
                await using var output = new FileStream(
                    manifest.PartialPath,
                    FileMode.Create,
                    FileAccess.Write,
                    FileShare.Read,
                    BufferSize,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                var buffer = new byte[BufferSize];
                long received = 0;
                while (true)
                {
                    var read = await input.ReadAsync(buffer, responseLease.OperationToken).ConfigureAwait(false);
                    if (read == 0)
                        break;
                    await output.WriteAsync(buffer.AsMemory(0, read), responseLease.OperationToken).ConfigureAwait(false);
                    received += read;
                    job.RecordBytes(null, read);
                    Publish(job, force: false);
                }

                if (manifest.Resource.TotalLength > 0 && received != manifest.Resource.TotalLength)
                    throw new IOException("单连接响应长度与探测结果不一致。 ");

                await output.FlushAsync(responseLease.OperationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
                job.RecordRequestSuccess(responseLatencyMilliseconds);
                await SaveManifestAsync(job, cancellationToken, force: true).ConfigureAwait(false);
                return;
            }
            catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
            {
                lastException = new TimeoutException("单连接下载超时。 ", exception);
                job.RecordRequestError();
                job.IncrementChunkRetry(-1);
                job.SetStatus(_tunnels.IsConnected ? DownloadTaskStatus.Downloading : DownloadTaskStatus.Reconnecting);
                Publish(job, force: true);
                if (attempt + 1 >= MaximumRetries)
                    break;
                await WaitOrBackoffAsync(attempt, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception exception) when (ShouldRetry(exception))
            {
                lastException = exception;
                job.RecordRequestError();
                job.IncrementChunkRetry(-1);
                job.SetStatus(_tunnels.IsConnected ? DownloadTaskStatus.Downloading : DownloadTaskStatus.Reconnecting);
                Publish(job, force: true);
                if (attempt + 1 >= MaximumRetries)
                    break;
                await WaitOrBackoffAsync(attempt, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                job.EndConnection();
            }
        }

        throw lastException ?? new IOException("单连接下载失败。 ");
    }

    private async Task TuneRangeTransferAsync(
        DownloadJobState job,
        RangeWorkQueue pending,
        AsyncConcurrencyGate gate,
        CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        var lastTick = Stopwatch.GetTimestamp();
        var dualTunnelProbe = false;
        var dualTunnelBaseline = 0d;
        var dualTunnelSamples = 0;
        var dualTunnelTotal = 0d;

        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            var now = Stopwatch.GetTimestamp();
            var interval = Stopwatch.GetElapsedTime(lastTick, now);
            lastTick = now;
            var window = job.TakeThroughputWindow(interval, pending.RemainingCount > 0);
            if (!window.HasBacklog)
                continue;

            var concurrencyChanged = false;
            if (job.Request.AutoTuneConcurrency && !dualTunnelProbe)
            {
                var next = Math.Min(job.ConcurrencyTuner.Observe(window), _maximumGlobalConnections);
                if (next != gate.Limit)
                {
                    gate.SetLimit(next);
                    job.SetConcurrency(next);
                    concurrencyChanged = true;
                    Publish(job, force: true);
                }
            }

            if (dualTunnelProbe)
            {
                dualTunnelTotal += window.BytesPerSecond;
                dualTunnelSamples++;
                if (dualTunnelSamples >= 2)
                {
                    var dualAverage = dualTunnelTotal / dualTunnelSamples;
                    if (!job.TunnelScalePolicy.ShouldKeepSecondTunnel(dualTunnelBaseline, dualAverage))
                        await _tunnels.RemoveSecondTunnelAsync().ConfigureAwait(false);
                    dualTunnelProbe = false;
                }
                continue;
            }

            if (concurrencyChanged)
                continue;

            if (job.TunnelScalePolicy.ShouldProbeSecondTunnel(window, gate.Limit, _tunnels.TunnelCount))
            {
                dualTunnelBaseline = window.BytesPerSecond;
                if (await _tunnels.TryAddSecondTunnelAsync(cancellationToken).ConfigureAwait(false))
                {
                    dualTunnelProbe = true;
                    dualTunnelSamples = 0;
                    dualTunnelTotal = 0;
                    Publish(job, force: true);
                }
            }
        }
    }

    private async Task FinalizeDownloadAsync(DownloadJobState job, CancellationToken cancellationToken)
    {
        var manifest = job.Manifest ?? throw new InvalidOperationException("Download manifest was not initialized.");
        var partial = new FileInfo(manifest.PartialPath);
        if (!partial.Exists)
            throw new IOException("本地临时文件不存在。 ");
        if (manifest.Resource.TotalLength > 0 && partial.Length != manifest.Resource.TotalLength)
            throw new IOException("本地文件长度校验失败。 ");

        if (manifest.Resource.ExpectedSha256 is { Length: > 0 } expected)
        {
            await using var input = new FileStream(
                manifest.PartialPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                BufferSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var actual = Convert.ToBase64String(await SHA256.HashDataAsync(input, cancellationToken).ConfigureAwait(false));
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromBase64String(actual),
                    Convert.FromBase64String(expected)))
                throw new IOException("SHA-256 校验失败，保留临时文件供检查。 ");
        }

        cancellationToken.ThrowIfCancellationRequested();
        File.Move(manifest.PartialPath, manifest.TargetPath);
        manifest.Completed = true;
        await SaveManifestAsync(job, cancellationToken, force: true).ConfigureAwait(false);
        job.SetStatus(DownloadTaskStatus.Completed);
    }

    private static void ApplyIfRange(HttpRequestMessage request, ResourceIdentity? resource)
    {
        if (resource?.EntityTag is { Length: > 0 } tag && !tag.StartsWith("W/", StringComparison.OrdinalIgnoreCase))
            request.Headers.IfRange = new RangeConditionHeaderValue(EntityTagHeaderValue.Parse(tag));
        else if (resource?.LastModifiedUtc is { } modified)
            request.Headers.IfRange = new RangeConditionHeaderValue(modified);
    }

    private static void ValidateRangeResponse(
        HttpResponseMessage response,
        DownloadRange requested,
        ResourceIdentity? expected)
    {
        var contentRange = response.Content.Headers.ContentRange;
        if (response.StatusCode != HttpStatusCode.PartialContent ||
            contentRange?.From != requested.Offset ||
            contentRange.To != requested.EndExclusive - 1 ||
            contentRange.Length != expected?.TotalLength)
            throw new ResourceChangedException("服务器返回的分片范围与请求不匹配。 ");

        if (expected?.EntityTag is { Length: > 0 } expectedTag &&
            !expectedTag.StartsWith("W/", StringComparison.OrdinalIgnoreCase) &&
            response.Headers.ETag is { } responseTag &&
            !string.Equals(expectedTag, responseTag.ToString(), StringComparison.Ordinal))
            throw new ResourceChangedException("分片响应的 ETag 与文件探测结果不同。 ");

        if (expected?.LastModifiedUtc is { } expectedModified &&
            response.Content.Headers.LastModified is { } responseModified &&
            expectedModified != responseModified)
            throw new ResourceChangedException("分片响应的 Last-Modified 与文件探测结果不同。 ");
    }
}
