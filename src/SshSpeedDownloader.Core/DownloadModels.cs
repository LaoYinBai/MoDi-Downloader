namespace SshSpeedDownloader.Core;

public enum DownloadTaskStatus
{
    Waiting,
    Inspecting,
    Connecting,
    Downloading,
    Paused,
    Reconnecting,
    Completed,
    Failed,
    Cancelled,
    ResourceChanged
}

public sealed record DownloadRequest(
    Uri SourceUri,
    string SaveDirectory,
    int InitialConcurrency = 8,
    bool AutoTuneConcurrency = true,
    long ChunkSizeBytes = 1_048_576);

public sealed record DownloadSegmentProgress(
    int Index,
    long Offset,
    long Length,
    long ReceivedBytes,
    bool IsComplete,
    int RetryCount);

public sealed record DownloadTaskSnapshot(
    Guid Id,
    string FileName,
    Uri SourceUri,
    string TargetPath,
    DownloadTaskStatus Status,
    long ReceivedBytes,
    long? TotalBytes,
    double BytesPerSecond,
    int ActiveConnections,
    int Concurrency,
    int RetryCount,
    TimeSpan? RemainingTime,
    bool SupportsRanges,
    bool CanResume,
    int CompletedChunkCount,
    int TotalChunkCount,
    string? Error,
    IReadOnlyList<DownloadSegmentProgress> Segments);

public sealed class DownloadManifest
{
    public Guid Id { get; set; }
    public string SourceUrl { get; set; } = "";
    public string FinalUrl { get; set; } = "";
    public string TargetPath { get; set; } = "";
    public string PartialPath { get; set; } = "";
    public ResourceIdentity Resource { get; set; } = new(0, false, null, null);
    public long ChunkSizeBytes { get; set; } = 1_048_576;
    public int RequestedConcurrency { get; set; } = 8;
    public bool AutoTuneConcurrency { get; set; } = true;
    public List<int> CompletedChunkIndexes { get; set; } = [];
    public long StreamBytesWritten { get; set; }
    public int RetryCount { get; set; }
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public bool Completed { get; set; }
}
