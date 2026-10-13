using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Desktop.Models;

public sealed class DesktopSettings
{
    public string? LastAccessRequestId { get; set; }
    public string DefaultDownloadDirectory { get; set; } = "";
    public bool HasCustomDefaultDownloadDirectory { get; set; }
    public int InitialConcurrency { get; set; } = 8;
    public bool AutoTuneConcurrency { get; set; } = true;
    public bool CompletionSoundEnabled { get; set; } = true;
    public int CompletionVolumePercent { get; set; } = 55;
}
