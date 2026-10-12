namespace SshSpeedDownloader.Core;

public readonly record struct CompletionFeedbackDecision(bool PlaySound, bool ShowNotification);

public sealed class CompletionFeedbackGate
{
    private readonly object _sync = new();
    private readonly HashSet<Guid> _handledTasks = [];
    private readonly TimeSpan _soundCooldown;
    private readonly TimeSpan _notificationCooldown;
    private DateTimeOffset? _lastSoundAt;
    private DateTimeOffset? _lastNotificationAt;

    public CompletionFeedbackGate(TimeSpan soundCooldown, TimeSpan notificationCooldown)
    {
        if (soundCooldown < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(soundCooldown));
        if (notificationCooldown < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(notificationCooldown));
        _soundCooldown = soundCooldown;
        _notificationCooldown = notificationCooldown;
    }

    public CompletionFeedbackDecision Register(Guid taskId, DateTimeOffset now, bool soundEnabled)
    {
        if (taskId == Guid.Empty)
            throw new ArgumentException("Task id must not be empty.", nameof(taskId));

        lock (_sync)
        {
            if (!_handledTasks.Add(taskId))
                return default;

            var playSound = soundEnabled && IsOutsideCooldown(_lastSoundAt, now, _soundCooldown);
            var showNotification = IsOutsideCooldown(_lastNotificationAt, now, _notificationCooldown);
            if (playSound)
                _lastSoundAt = now;
            if (showNotification)
                _lastNotificationAt = now;

            return new CompletionFeedbackDecision(playSound, showNotification);
        }
    }

    public void MarkHandledWithoutFeedback(Guid taskId)
    {
        if (taskId == Guid.Empty)
            return;
        lock (_sync)
            _handledTasks.Add(taskId);
    }

    private static bool IsOutsideCooldown(DateTimeOffset? previous, DateTimeOffset now, TimeSpan cooldown) =>
        previous is null || now - previous.Value >= cooldown;
}
