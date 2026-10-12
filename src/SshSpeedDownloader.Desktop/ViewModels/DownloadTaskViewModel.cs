using CommunityToolkit.Mvvm.ComponentModel;
using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Desktop.ViewModels;

public sealed class DownloadTaskViewModel : ObservableObject
{
    private DownloadTaskSnapshot _snapshot;
    private IReadOnlyList<DownloadSegmentViewModel> _segments = [];

    public DownloadTaskViewModel(DownloadTaskSnapshot snapshot)
    {
        _snapshot = snapshot;
        UpdateSegments(snapshot);
    }

    public Guid Id => _snapshot.Id;
    public string FileName => _snapshot.FileName;
    public string StatusText => _snapshot.Status switch
    {
        DownloadTaskStatus.Waiting => "等待中",
        DownloadTaskStatus.Inspecting => "检测资源",
        DownloadTaskStatus.Connecting => "连接中",
        DownloadTaskStatus.Downloading => "下载中",
        DownloadTaskStatus.Paused => "已暂停",
        DownloadTaskStatus.Reconnecting => "重连中",
        DownloadTaskStatus.Completed => "已完成",
        DownloadTaskStatus.Failed => "失败",
        DownloadTaskStatus.Cancelled => "已取消",
        DownloadTaskStatus.ResourceChanged => "资源已变化",
        _ => "未知"
    };
    public double Progress => _snapshot.TotalBytes is > 0
        ? Math.Clamp(100d * _snapshot.ReceivedBytes / _snapshot.TotalBytes.Value, 0, 100)
        : 0;
    public string PercentText => _snapshot.TotalBytes is > 0 ? $"{Progress:0.0}%" : "已接收";
    public string SpeedText => FormatRate(_snapshot.BytesPerSecond);
    public string SizeText => $"{FormatBytes(_snapshot.ReceivedBytes)} / {(_snapshot.TotalBytes is { } total ? FormatBytes(total) : "未知大小")}";
    public string RemainingText => _snapshot.RemainingTime is { } remaining ? $"剩余 {FormatDuration(remaining)}" : "";
    public string ConnectionsText => $"{_snapshot.ActiveConnections} / {_snapshot.Concurrency} 连接";
    public string ChunkText => _snapshot.SupportsRanges
        ? $"分片 {_snapshot.CompletedChunkCount} / {_snapshot.TotalChunkCount}"
        : "单连接流式传输";
    public string RetryText => $"重试 {_snapshot.RetryCount} 次";
    public string ErrorText => _snapshot.Error ?? "";
    public string SourceText => UrlSafety.RedactForLog(_snapshot.SourceUri);
    public string TargetPath => _snapshot.TargetPath;
    public bool HasError => !string.IsNullOrWhiteSpace(_snapshot.Error);
    public bool CanPause => _snapshot.Status is DownloadTaskStatus.Waiting or DownloadTaskStatus.Inspecting or
        DownloadTaskStatus.Connecting or DownloadTaskStatus.Downloading or DownloadTaskStatus.Reconnecting;
    public bool CanResume => _snapshot.Status == DownloadTaskStatus.Paused;
    public bool CanCancel => _snapshot.Status is not (DownloadTaskStatus.Completed or DownloadTaskStatus.Cancelled);
    public bool CanRetry => _snapshot.Status is DownloadTaskStatus.Failed or DownloadTaskStatus.ResourceChanged;
    public bool CanOpen => _snapshot.Status == DownloadTaskStatus.Completed;
    public IReadOnlyList<DownloadSegmentViewModel> Segments => _segments;

    public void Update(DownloadTaskSnapshot snapshot)
    {
        _snapshot = snapshot;
        UpdateSegments(snapshot);
        OnPropertyChanged(string.Empty);
    }

    private void UpdateSegments(DownloadTaskSnapshot snapshot) =>
        _segments = snapshot.Segments.Select(segment => new DownloadSegmentViewModel(segment)).ToArray();

    private static string FormatRate(double bytesPerSecond) => $"{bytesPerSecond / (1024d * 1024d):0.00} MiB/s";

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KiB", "MiB", "GiB", "TiB"];
        var value = (double)Math.Max(0, bytes);
        var index = 0;
        while (value >= 1024 && index < units.Length - 1)
        {
            value /= 1024;
            index++;
        }
        return $"{value:0.##} {units[index]}";
    }

    private static string FormatDuration(TimeSpan duration) => duration.TotalHours >= 1
        ? $"{(int)duration.TotalHours} 小时 {duration.Minutes} 分"
        : duration.TotalMinutes >= 1 ? $"{duration.Minutes} 分 {duration.Seconds} 秒" : $"{Math.Max(1, duration.Seconds)} 秒";
}

public sealed class DownloadSegmentViewModel(DownloadSegmentProgress snapshot)
{
    public string Label => $"分片 {snapshot.Index + 1}";
    public double Progress => snapshot.Length > 0
        ? Math.Clamp(100d * snapshot.ReceivedBytes / snapshot.Length, 0, 100)
        : 0;
    public string BytesText => $"{FormatBytes(snapshot.ReceivedBytes)} / {FormatBytes(snapshot.Length)}";
    public int RetryCount => snapshot.RetryCount;

    private static string FormatBytes(long bytes) => bytes >= 1024 * 1024
        ? $"{bytes / (1024d * 1024d):0.##} MiB"
        : bytes >= 1024 ? $"{bytes / 1024d:0.##} KiB" : $"{bytes} B";
}
