using System.Collections.Concurrent;
using System.Diagnostics;
using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Transport;

internal sealed class DownloadJobState
{
    private readonly object _sync = new();
    private readonly object _rateSync = new();
    private readonly ConcurrentDictionary<int, ActiveSegment> _activeSegments = new();
    private readonly ConcurrentDictionary<int, byte> _completedChunks = new();
    private readonly ConcurrentQueue<double> _latencies = new();
    private long _completedBytes;
    private long _streamBytes;
    private long _windowBytes;
    private int _windowRequests;
    private int _windowErrors;
    private int _retryCount;
    private int _activeConnections;
    private long _lastUiTicks;
    private long _lastPublishTicks;
    private long _lastManifestSaveTicks;
    private int _lastManifestSaveChunkCount;
    private long _lastUiBytes;
    private double _smoothedBytesPerSecond;
    private DownloadTaskStatus _status;
    private string? _error;
    private DownloadManifest? _manifest;
    private string _fileName;
    private string _targetPath = "";
    private long _totalBytes;
    private int _supportsRanges;
    private int _currentConcurrency;
    private int _totalChunkCount;

    public DownloadJobState(DownloadRequest request)
    {
        Id = Guid.NewGuid();
        Request = request;
        _status = DownloadTaskStatus.Waiting;
        var leaf = Path.GetFileName(request.SourceUri.AbsolutePath);
        _fileName = DownloadFileName.Sanitize(string.IsNullOrWhiteSpace(leaf) ? "download.bin" : leaf);
        _currentConcurrency = request.InitialConcurrency;
        ConcurrencyTuner = new AdaptiveConcurrencyController(request.InitialConcurrency);
        TunnelScalePolicy = new TunnelScalePolicy();
    }

    public DownloadJobState(DownloadManifest manifest)
        : this(new DownloadRequest(
            new Uri(manifest.SourceUrl),
            Path.GetDirectoryName(manifest.TargetPath) ?? "",
            manifest.RequestedConcurrency,
            manifest.AutoTuneConcurrency,
            manifest.ChunkSizeBytes))
    {
        Id = manifest.Id;
        SetManifest(manifest, restored: true);
        IsRestored = true;
        _status = manifest.Completed ? DownloadTaskStatus.Completed : DownloadTaskStatus.Paused;
    }

    public Guid Id { get; }
    public DownloadRequest Request { get; }
    public AdaptiveConcurrencyController ConcurrencyTuner { get; private set; }
    public TunnelScalePolicy TunnelScalePolicy { get; private set; }
    public AsyncConcurrencyGate? ConcurrencyGate { get; set; }
    public CancellationTokenSource? RunCancellation { get; set; }
    public Task? Runner { get; set; }
    public SemaphoreSlim ManifestSaveGate { get; } = new(1, 1);
    public bool IsRestored { get; set; }
    public bool PauseRequested { get; set; }
    public bool CancelRequested { get; set; }

    public DownloadManifest? Manifest
    {
        get
        {
            lock (_sync)
                return _manifest;
        }
    }

    public string TargetPath
    {
        get
        {
            lock (_sync)
                return _targetPath;
        }
    }

    public string PartialPath
    {
        get
        {
            lock (_sync)
                return _manifest?.PartialPath ?? "";
        }
    }

    public bool SupportsRanges => Volatile.Read(ref _supportsRanges) != 0;
    public long TotalBytes => Interlocked.Read(ref _totalBytes);
    public int CurrentConcurrency => Volatile.Read(ref _currentConcurrency);
    public int ActiveConnections => Volatile.Read(ref _activeConnections);
    public int RetryCount => Volatile.Read(ref _retryCount);
    public int TotalChunkCount => Volatile.Read(ref _totalChunkCount);
    public int CompletedChunkCount => _completedChunks.Count;
    public bool HasStableResumeValidator => _manifest is { } manifest &&
        (manifest.Resource.EntityTag is { Length: > 0 } entityTag &&
         !entityTag.StartsWith("W/", StringComparison.OrdinalIgnoreCase) ||
         manifest.Resource.LastModifiedUtc is not null);

    public void SetStatus(DownloadTaskStatus status, string? error = null)
    {
        lock (_sync)
        {
            _status = status;
            _error = error;
        }
    }

    public void SetManifest(DownloadManifest manifest, bool restored = false)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        lock (_sync)
        {
            _manifest = manifest;
            _targetPath = manifest.TargetPath;
            _fileName = Path.GetFileName(manifest.TargetPath);
            _totalBytes = manifest.Resource.TotalLength;
            _supportsRanges = manifest.Resource.AcceptsRanges ? 1 : 0;
            _currentConcurrency = manifest.RequestedConcurrency;
            _streamBytes = restored ? 0 : manifest.StreamBytesWritten;
        }

        if (!restored)
        {
            _completedChunks.Clear();
            Interlocked.Exchange(ref _completedBytes, 0);
        }

        foreach (var index in manifest.CompletedChunkIndexes)
            _completedChunks.TryAdd(index, 0);
        Interlocked.Exchange(ref _retryCount, manifest.RetryCount);

        if (manifest.Resource.AcceptsRanges && manifest.Resource.TotalLength > 0)
        {
            try
            {
                var rangeCount = RangePartition.Count(manifest.Resource.TotalLength, manifest.ChunkSizeBytes);
                Volatile.Write(ref _totalChunkCount, rangeCount);
                long completedBytes = 0;
                foreach (var index in manifest.CompletedChunkIndexes)
                {
                    if ((uint)index < (uint)rangeCount)
                        completedBytes = checked(completedBytes + RangePartition.Get(
                            manifest.Resource.TotalLength,
                            manifest.ChunkSizeBytes,
                            index).Length);
                }
                Interlocked.Exchange(ref _completedBytes, completedBytes);
            }
            catch (OverflowException)
            {
                Volatile.Write(ref _totalChunkCount, 0);
            }
            catch (ArgumentOutOfRangeException)
            {
                Volatile.Write(ref _totalChunkCount, 0);
            }
        }
    }

    public void SetFile(string fileName, string targetPath)
    {
        lock (_sync)
        {
            _fileName = fileName;
            _targetPath = targetPath;
        }
    }

    public void SetRangeMetadata(ResourceIdentity resource, int chunkCount)
    {
        lock (_sync)
        {
            _totalBytes = resource.TotalLength;
            _supportsRanges = resource.AcceptsRanges ? 1 : 0;
            _totalChunkCount = chunkCount;
        }
    }

    public void SetConcurrency(int concurrency)
    {
        Volatile.Write(ref _currentConcurrency, Math.Clamp(concurrency, 1, 64));
    }

    public long GetReceivedBytes() => SupportsRanges
        ? Interlocked.Read(ref _completedBytes) + _activeSegments.Values.Sum(segment => Interlocked.Read(ref segment.ReceivedBytes))
        : Interlocked.Read(ref _streamBytes);

    public bool ShouldPublish()
    {
        var now = Stopwatch.GetTimestamp();
        var previous = Interlocked.Read(ref _lastPublishTicks);
        if (previous != 0 && Stopwatch.GetElapsedTime(previous, now) < TimeSpan.FromMilliseconds(250))
            return false;

        Interlocked.Exchange(ref _lastPublishTicks, now);
        return true;
    }

    public bool TryBeginManifestSave(bool force)
    {
        var now = Stopwatch.GetTimestamp();
        var previousTicks = Interlocked.Read(ref _lastManifestSaveTicks);
        var completedChunks = CompletedChunkCount;
        var previousChunks = Volatile.Read(ref _lastManifestSaveChunkCount);
        if (!force && previousTicks != 0 && completedChunks - previousChunks < 32 &&
            Stopwatch.GetElapsedTime(previousTicks, now) < TimeSpan.FromSeconds(1))
            return false;
        if (Interlocked.CompareExchange(ref _lastManifestSaveTicks, now, previousTicks) != previousTicks)
            return false;

        Volatile.Write(ref _lastManifestSaveChunkCount, completedChunks);
        return true;
    }

    public void ResetForRestart()
    {
        _activeSegments.Clear();
        _completedChunks.Clear();
        while (_latencies.TryDequeue(out _)) { }
        Interlocked.Exchange(ref _completedBytes, 0);
        Interlocked.Exchange(ref _streamBytes, 0);
        Interlocked.Exchange(ref _windowBytes, 0);
        Interlocked.Exchange(ref _windowRequests, 0);
        Interlocked.Exchange(ref _windowErrors, 0);
        Interlocked.Exchange(ref _retryCount, 0);
        Interlocked.Exchange(ref _activeConnections, 0);
        Interlocked.Exchange(ref _totalChunkCount, 0);
        Interlocked.Exchange(ref _supportsRanges, 0);
        Interlocked.Exchange(ref _lastManifestSaveTicks, 0);
        Volatile.Write(ref _lastManifestSaveChunkCount, 0);
        ConcurrencyTuner = new AdaptiveConcurrencyController(Request.InitialConcurrency);
        TunnelScalePolicy = new TunnelScalePolicy();
        ConcurrencyGate = null;
        lock (_sync)
        {
            _manifest = null;
            _targetPath = "";
            _totalBytes = 0;
            _status = DownloadTaskStatus.Waiting;
            _error = null;
        }
        lock (_rateSync)
        {
            _lastUiTicks = 0;
            _lastUiBytes = 0;
            _smoothedBytesPerSecond = 0;
        }
        Interlocked.Exchange(ref _lastPublishTicks, 0);
        Volatile.Write(ref _currentConcurrency, Request.InitialConcurrency);
    }

    public bool IsChunkComplete(int index) => _completedChunks.ContainsKey(index);

    public void BeginChunk(DownloadRange range)
    {
        _activeSegments[range.Index] = new ActiveSegment(range);
    }

    public void SetChunkBytes(int index, long receivedBytes)
    {
        if (_activeSegments.TryGetValue(index, out var segment))
            Interlocked.Exchange(ref segment.ReceivedBytes, receivedBytes);
    }

    public int IncrementChunkRetry(int index)
    {
        Interlocked.Increment(ref _retryCount);
        return _activeSegments.TryGetValue(index, out var segment)
            ? Interlocked.Increment(ref segment.RetryCount)
            : 1;
    }

    public void CompleteChunk(DownloadRange range)
    {
        _activeSegments.TryRemove(range.Index, out _);
        if (_completedChunks.TryAdd(range.Index, 0))
            Interlocked.Add(ref _completedBytes, range.Length);
    }

    public IReadOnlyList<int> CompletedChunkIndexes() => _completedChunks.Keys.Order().ToArray();

    public IReadOnlyList<DownloadSegmentProgress> ActiveSegmentSnapshots() =>
        _activeSegments.Values
            .Select(segment => new DownloadSegmentProgress(
                segment.Range.Index,
                segment.Range.Offset,
                segment.Range.Length,
                Interlocked.Read(ref segment.ReceivedBytes),
                false,
                Volatile.Read(ref segment.RetryCount)))
            .OrderBy(segment => segment.Index)
            .ToArray();

    public void SetStreamBytes(long bytes) => Interlocked.Exchange(ref _streamBytes, Math.Max(0, bytes));

    public void ResetStreamBytes() => Interlocked.Exchange(ref _streamBytes, 0);

    public void BeginConnection() => Interlocked.Increment(ref _activeConnections);

    public void EndConnection() => Interlocked.Decrement(ref _activeConnections);

    public void RecordBytes(int? chunkIndex, int count)
    {
        Interlocked.Add(ref _windowBytes, count);
        if (chunkIndex is { } index && _activeSegments.TryGetValue(index, out var segment))
            Interlocked.Add(ref segment.ReceivedBytes, count);
        else
            Interlocked.Add(ref _streamBytes, count);
    }

    public void RecordRequestSuccess(double latencyMilliseconds)
    {
        Interlocked.Increment(ref _windowRequests);
        _latencies.Enqueue(Math.Max(0, latencyMilliseconds));
        while (_latencies.Count > 128)
            _latencies.TryDequeue(out _);
    }

    public void RecordRequestError() => Interlocked.Increment(ref _windowErrors);

    public void ResetThroughputWindow()
    {
        Interlocked.Exchange(ref _windowBytes, 0);
        Interlocked.Exchange(ref _windowRequests, 0);
        Interlocked.Exchange(ref _windowErrors, 0);
        while (_latencies.TryDequeue(out _)) { }
    }

    public ThroughputWindow TakeThroughputWindow(TimeSpan interval, bool hasBacklog)
    {
        var bytes = Interlocked.Exchange(ref _windowBytes, 0);
        var requests = Interlocked.Exchange(ref _windowRequests, 0);
        var errors = Interlocked.Exchange(ref _windowErrors, 0);
        var samples = new List<double>();
        while (_latencies.TryDequeue(out var latency))
            samples.Add(latency);
        samples.Sort();
        var p95 = samples.Count == 0 ? 0 : samples[(int)Math.Ceiling(samples.Count * 0.95) - 1];
        var attempts = requests + errors;
        return new ThroughputWindow(
            interval.TotalSeconds <= 0 ? 0 : bytes / interval.TotalSeconds,
            p95,
            attempts == 0 ? 0 : (double)errors / attempts,
            hasBacklog);
    }

    public DownloadTaskSnapshot CreateSnapshot()
    {
        DownloadTaskStatus status;
        string? error;
        string fileName;
        string targetPath;
        Uri sourceUri;
        long total;
        bool canResume;
        lock (_sync)
        {
            status = _status;
            error = _error;
            fileName = _fileName;
            targetPath = _targetPath;
            sourceUri = Request.SourceUri;
            total = _totalBytes;
            canResume = _manifest?.Resource.AcceptsRanges == true &&
                ((_manifest.Resource.EntityTag is { Length: > 0 } tag &&
                  !tag.StartsWith("W/", StringComparison.OrdinalIgnoreCase)) ||
                 _manifest.Resource.LastModifiedUtc is not null);
        }

        var received = GetReceivedBytes();
        if (status == DownloadTaskStatus.Completed && total > 0)
            received = total;
        if (total > 0)
            received = Math.Min(received, total);

        var now = Stopwatch.GetTimestamp();
        double rate;
        lock (_rateSync)
        {
            if (_lastUiTicks == 0)
            {
                _lastUiTicks = now;
                _lastUiBytes = received;
            }
            else
            {
                var elapsed = (now - _lastUiTicks) / (double)Stopwatch.Frequency;
                if (elapsed >= 0.2)
                {
                    var delta = Math.Max(0, received - _lastUiBytes);
                    var instant = delta / elapsed;
                    _smoothedBytesPerSecond = _smoothedBytesPerSecond <= 0
                        ? instant
                        : (_smoothedBytesPerSecond * 0.65) + (instant * 0.35);
                    _lastUiTicks = now;
                    _lastUiBytes = received;
                }
                else if (status is not (DownloadTaskStatus.Downloading or DownloadTaskStatus.Reconnecting))
                {
                    _smoothedBytesPerSecond = 0;
                }
            }
            rate = _smoothedBytesPerSecond;
        }

        TimeSpan? remaining = total > received && rate > 0
            ? TimeSpan.FromSeconds((total - received) / rate)
            : null;
        return new DownloadTaskSnapshot(
            Id,
            fileName,
            sourceUri,
            targetPath,
            status,
            received,
            total > 0 ? total : null,
            rate,
            ActiveConnections,
            CurrentConcurrency,
            RetryCount,
            remaining,
            SupportsRanges,
            canResume,
            CompletedChunkCount,
            TotalChunkCount,
            error,
            ActiveSegmentSnapshots());
    }

    private sealed class ActiveSegment(DownloadRange range)
    {
        public DownloadRange Range { get; } = range;
        public long ReceivedBytes;
        public int RetryCount;
    }
}
