using System.Runtime.InteropServices;
using SshSpeedDownloader.Core;
using Forms = System.Windows.Forms;

namespace SshSpeedDownloader.Desktop.Services;

public sealed class WindowsCompletionFeedbackService : IDisposable
{
    private readonly CompletionFeedbackGate _gate = new(
        soundCooldown: TimeSpan.FromSeconds(1.6),
        notificationCooldown: TimeSpan.FromSeconds(1.2));
    private readonly Forms.NotifyIcon? _notificationIcon;
    private int _disposed;

    public WindowsCompletionFeedbackService()
    {
        if (!OperatingSystem.IsWindows())
            return;

        try
        {
            _notificationIcon = new Forms.NotifyIcon
            {
                Icon = System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath!) ?? System.Drawing.SystemIcons.Application,
                Text = "MoDi Downloader",
                Visible = true
            };
            _notificationIcon.BalloonTipTitle = "MoDi Downloader";
            _notificationIcon.BalloonTipIcon = Forms.ToolTipIcon.Info;
            _notificationIcon.BalloonTipClicked += (_, _) => NotificationActivated?.Invoke(this, EventArgs.Empty);
            _notificationIcon.DoubleClick += (_, _) => NotificationActivated?.Invoke(this, EventArgs.Empty);
        }
        catch
        {
            _notificationIcon?.Dispose();
        }
    }

    public event EventHandler? NotificationActivated;

    public void NotifyCompleted(Guid taskId, string fileName, bool soundEnabled, int volumePercent)
    {
        if (Volatile.Read(ref _disposed) != 0)
            return;

        var decision = _gate.Register(taskId, DateTimeOffset.UtcNow, soundEnabled);
        if (decision.ShowNotification && _notificationIcon is not null)
        {
            try
            {
                _notificationIcon.BalloonTipText = $"下载完成：{fileName}\n点击打开 MoDi Downloader。";
                _notificationIcon.ShowBalloonTip(2500);
            }
            catch
            {
            }
        }

        if (decision.PlaySound && volumePercent > 0)
            _ = Task.Run(() => PcmCompletionChime.Play(volumePercent));
    }

    public void MarkHandledWithoutFeedback(Guid taskId) => _gate.MarkHandledWithoutFeedback(taskId);

    public void Preview(int volumePercent)
    {
        if (volumePercent > 0 && Volatile.Read(ref _disposed) == 0)
            _ = Task.Run(() => PcmCompletionChime.Play(volumePercent));
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        _notificationIcon?.Dispose();
    }

    private static class PcmCompletionChime
    {
        private const uint SoundMemory = 0x0004;
        private const uint SoundNoDefault = 0x0002;
        private static readonly Lazy<byte[]> Clip = new(() =>
        {
            using var source = typeof(WindowsCompletionFeedbackService).Assembly
                .GetManifestResourceStream("MoDiDownloader.CompletionSound.wav")
                ?? throw new InvalidDataException("The completion sound resource is unavailable.");
            using var bytes = new MemoryStream();
            source.CopyTo(bytes);
            return bytes.ToArray();
        });

        public static void Play(int volumePercent)
        {
            if (!OperatingSystem.IsWindows())
                return;

            try
            {
                var wav = CompletionSoundClip.WithVolume(Clip.Value, volumePercent);
                _ = PlaySound(wav, IntPtr.Zero, SoundMemory | SoundNoDefault);
            }
            catch
            {
            }
        }

        [DllImport("winmm.dll", EntryPoint = "PlaySoundW", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool PlaySound(byte[] sound, IntPtr module, uint flags);
    }
}
