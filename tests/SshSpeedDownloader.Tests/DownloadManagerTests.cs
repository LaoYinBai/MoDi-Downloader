using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using SshSpeedDownloader.Core;
using SshSpeedDownloader.Transport;

namespace SshSpeedDownloader.Tests;

public sealed class DownloadManagerTests
{
    [Fact]
    public async Task RangeDownloadWritesTheExactSourceBytesToTheFinalFile()
    {
        var bytes = CreatePayload(1_572_907);
        var handler = new InMemoryHttpHandler(bytes, supportsRanges: true);
        using var client = new HttpClient(handler);
        var tunnelPool = new TestTunnelPool(client);
        var root = CreateTemporaryDirectory();

        try
        {
            await using var manager = new DownloadManager(tunnelPool, new JsonDownloadManifestStore(Path.Combine(root, "tasks")));
            var id = await manager.AddAsync(
                new DownloadRequest(
                    new Uri("https://download.example.test/payload.bin"),
                    root,
                    InitialConcurrency: 4,
                    AutoTuneConcurrency: false,
                    ChunkSizeBytes: 512 * 1024));

            var snapshot = await WaitForStatusAsync(manager, id, DownloadTaskStatus.Completed);
            Assert.NotNull(snapshot.TotalBytes);
            Assert.Equal(bytes.LongLength, snapshot.TotalBytes);
            Assert.Equal(bytes.LongLength, new FileInfo(snapshot.TargetPath).Length);
            Assert.Equal(bytes, await File.ReadAllBytesAsync(snapshot.TargetPath));
            Assert.Equal(4, handler.RangeRequestCount);
            Assert.Equal(1, handler.ProbeRequestCount);
            Assert.Equal(0, handler.FullStreamRequestCount);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ResourceThatIgnoresRangeFallsBackToOneSequentialStream()
    {
        var bytes = CreatePayload(131_123);
        var handler = new InMemoryHttpHandler(bytes, supportsRanges: false);
        using var client = new HttpClient(handler);
        var root = CreateTemporaryDirectory();

        try
        {
            await using var manager = new DownloadManager(new TestTunnelPool(client), new JsonDownloadManifestStore(Path.Combine(root, "tasks")));
            var id = await manager.AddAsync(
                new DownloadRequest(
                    new Uri("https://download.example.test/stream.bin"),
                    root,
                    InitialConcurrency: 8,
                    AutoTuneConcurrency: false));

            var snapshot = await WaitForStatusAsync(manager, id, DownloadTaskStatus.Completed);
            Assert.Equal(bytes, await File.ReadAllBytesAsync(snapshot.TargetPath));
            Assert.Equal(1, handler.ProbeRequestCount);
            Assert.Equal(0, handler.RangeRequestCount);
            Assert.Equal(1, handler.FullStreamRequestCount);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PausedRangeDownloadResumesOnlyIncompleteChunks()
    {
        var bytes = CreatePayload(4 * 1024 * 1024);
        var handler = new InMemoryHttpHandler(bytes, supportsRanges: true, responseDelay: TimeSpan.FromMilliseconds(20));
        using var client = new HttpClient(handler);
        var root = CreateTemporaryDirectory();

        try
        {
            await using var manager = new DownloadManager(
                new TestTunnelPool(client),
                new JsonDownloadManifestStore(Path.Combine(root, "tasks")),
                maximumGlobalConnections: 2);
            var id = await manager.AddAsync(
                new DownloadRequest(
                    new Uri("https://download.example.test/resume.bin"),
                    root,
                    InitialConcurrency: 2,
                    AutoTuneConcurrency: false,
                    ChunkSizeBytes: 64 * 1024));

            using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
            {
                while (manager.GetSnapshot(id).CompletedChunkCount < 2)
                    await Task.Delay(10, timeout.Token);
            }

            var completedBeforePause = manager.GetSnapshot(id).CompletedChunkCount;
            await manager.PauseAsync(id);
            Assert.Equal(DownloadTaskStatus.Paused, manager.GetSnapshot(id).Status);
            Assert.True(completedBeforePause >= 2);
            var rangeRequestsAtPause = handler.RangeRequestCount;

            await manager.ResumeAsync(id);
            var snapshot = await WaitForStatusAsync(manager, id, DownloadTaskStatus.Completed);

            Assert.Equal(bytes, await File.ReadAllBytesAsync(snapshot.TargetPath));
            Assert.Equal(64, snapshot.CompletedChunkCount);
            Assert.True(handler.RangeRequestCount - rangeRequestsAtPause <= 64 - completedBeforePause);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static byte[] CreatePayload(int size)
    {
        var payload = new byte[size];
        for (var index = 0; index < payload.Length; index++)
            payload[index] = (byte)(index % 251);
        return payload;
    }

    private static string CreateTemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), $"modi-download-engine-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    private static async Task<DownloadTaskSnapshot> WaitForStatusAsync(
        DownloadManager manager,
        Guid id,
        DownloadTaskStatus expected)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (!timeout.IsCancellationRequested)
        {
            var snapshot = manager.GetSnapshot(id);
            if (snapshot.Status == expected)
                return snapshot;
            if (snapshot.Status is DownloadTaskStatus.Failed or DownloadTaskStatus.ResourceChanged)
                throw new InvalidOperationException(snapshot.Error ?? snapshot.Status.ToString());
            await Task.Delay(25, timeout.Token);
        }

        throw new TimeoutException($"Task did not reach {expected}.");
    }

    private sealed class TestTunnelPool(HttpClient client) : ITunneledHttpClientPool
    {
        public bool IsConnected => true;
        public int TunnelCount => 1;

        public ITunneledHttpClientLease AcquireHttpClient() => new TestLease(client);
        public Task WaitUntilConnectedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<bool> TryAddSecondTunnelAsync(CancellationToken cancellationToken) => Task.FromResult(false);
        public Task RemoveSecondTunnelAsync() => Task.CompletedTask;

        private sealed class TestLease(HttpClient client) : ITunneledHttpClientLease
        {
            public Guid TunnelId { get; } = Guid.NewGuid();
            public HttpClient HttpClient { get; } = client;
            public void Dispose() { }
        }
    }

    private sealed class InMemoryHttpHandler(
        byte[] payload,
        bool supportsRanges,
        TimeSpan? responseDelay = null) : HttpMessageHandler
    {
        private static readonly DateTimeOffset LastModified = new(2026, 10, 11, 12, 0, 0, TimeSpan.Zero);
        private int _probeRequests;
        private int _rangeRequests;
        private int _fullStreamRequests;

        public int ProbeRequestCount => Volatile.Read(ref _probeRequests);
        public int RangeRequestCount => Volatile.Read(ref _rangeRequests);
        public int FullStreamRequestCount => Volatile.Read(ref _fullStreamRequests);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (responseDelay is { } delay)
                await Task.Delay(delay, cancellationToken);
            var requestedRange = request.Headers.Range?.Ranges.SingleOrDefault();
            if (requestedRange is not null && supportsRanges)
            {
                var from = requestedRange.From ?? 0;
                var to = requestedRange.To ?? payload.LongLength - 1;
                if (from == 0 && to == 0)
                    Interlocked.Increment(ref _probeRequests);
                else
                    Interlocked.Increment(ref _rangeRequests);

                var slice = payload.AsMemory(checked((int)from), checked((int)(to - from + 1))).ToArray();
                var response = new HttpResponseMessage(HttpStatusCode.PartialContent)
                {
                    Content = new ByteArrayContent(slice),
                    RequestMessage = request
                };
                response.Content.Headers.ContentRange = new ContentRangeHeaderValue(from, to, payload.LongLength);
                response.Content.Headers.LastModified = LastModified;
                response.Headers.AcceptRanges.Add("bytes");
                return response;
            }

            if (requestedRange is not null)
                Interlocked.Increment(ref _probeRequests);
            else
                Interlocked.Increment(ref _fullStreamRequests);

            var full = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(payload),
                RequestMessage = request
            };
            full.Content.Headers.LastModified = LastModified;
            return full;
        }
    }
}
