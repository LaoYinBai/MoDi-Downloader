using System.Buffers.Binary;
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
                Icon = System.Drawing.SystemIcons.Application,
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
        private const int SampleRate = 22_050;
        private const double DurationSeconds = 0.38;
        private const uint SoundMemory = 0x0004;
        private const uint SoundNoDefault = 0x0002;

        public static void Play(int volumePercent)
        {
            if (!OperatingSystem.IsWindows())
                return;

            try
            {
                var wav = CreateWave(Math.Clamp(volumePercent, 0, 100));
                _ = PlaySound(wav, IntPtr.Zero, SoundMemory | SoundNoDefault);
            }
            catch
            {
            }
        }

        private static byte[] CreateWave(int volumePercent)
        {
            var sampleCount = (int)(SampleRate * DurationSeconds);
            var dataLength = sampleCount * sizeof(short);
            var wave = new byte[44 + dataLength];
            "RIFF"u8.CopyTo(wave);
            BinaryPrimitives.WriteInt32LittleEndian(wave.AsSpan(4), wave.Length - 8);
            "WAVE"u8.CopyTo(wave.AsSpan(8));
            "fmt "u8.CopyTo(wave.AsSpan(12));
            BinaryPrimitives.WriteInt32LittleEndian(wave.AsSpan(16), 16);
            BinaryPrimitives.WriteInt16LittleEndian(wave.AsSpan(20), 1);
            BinaryPrimitives.WriteInt16LittleEndian(wave.AsSpan(22), 1);
            BinaryPrimitives.WriteInt32LittleEndian(wave.AsSpan(24), SampleRate);
            BinaryPrimitives.WriteInt32LittleEndian(wave.AsSpan(28), SampleRate * sizeof(short));
            BinaryPrimitives.WriteInt16LittleEndian(wave.AsSpan(32), sizeof(short));
            BinaryPrimitives.WriteInt16LittleEndian(wave.AsSpan(34), 16);
            "data"u8.CopyTo(wave.AsSpan(36));
            BinaryPrimitives.WriteInt32LittleEndian(wave.AsSpan(40), dataLength);

            var volume = volumePercent / 100d;
            for (var sample = 0; sample < sampleCount; sample++)
            {
                var time = sample / (double)SampleRate;
                var attack = Math.Min(1, time / 0.008);
                var decay = Math.Exp(-5.8 * time);
                var tone = Math.Sin(2 * Math.PI * 880 * time) + 0.42 * Math.Sin(2 * Math.PI * 1320 * time);
                var value = (short)Math.Clamp(tone * attack * decay * volume * 4_900, short.MinValue, short.MaxValue);
                BinaryPrimitives.WriteInt16LittleEndian(wave.AsSpan(44 + sample * sizeof(short)), value);
            }

            return wave;
        }

        [DllImport("winmm.dll", EntryPoint = "PlaySoundW", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool PlaySound(byte[] sound, IntPtr module, uint flags);
    }
}
