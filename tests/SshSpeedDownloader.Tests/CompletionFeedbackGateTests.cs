using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Tests;

public sealed class CompletionFeedbackGateTests
{
    [Fact]
    public void SignalsOnlyOncePerTaskAndRateLimitsNearSimultaneousCompletions()
    {
        var gate = new CompletionFeedbackGate(
            soundCooldown: TimeSpan.FromSeconds(2),
            notificationCooldown: TimeSpan.FromSeconds(3));
        var now = DateTimeOffset.UtcNow;
        var firstId = Guid.NewGuid();
        var secondId = Guid.NewGuid();

        Assert.Equal(new CompletionFeedbackDecision(true, true), gate.Register(firstId, now, soundEnabled: true));
        Assert.Equal(new CompletionFeedbackDecision(false, false), gate.Register(firstId, now.AddMilliseconds(50), soundEnabled: true));
        Assert.Equal(new CompletionFeedbackDecision(false, false), gate.Register(secondId, now.AddMilliseconds(100), soundEnabled: true));
        Assert.Equal(new CompletionFeedbackDecision(true, true), gate.Register(Guid.NewGuid(), now.AddSeconds(4), soundEnabled: true));
    }

    [Fact]
    public void DisabledSoundStillAllowsOneNotificationPerCooldownWindow()
    {
        var gate = new CompletionFeedbackGate(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
        var now = DateTimeOffset.UtcNow;

        Assert.Equal(new CompletionFeedbackDecision(false, true), gate.Register(Guid.NewGuid(), now, soundEnabled: false));
        Assert.Equal(new CompletionFeedbackDecision(false, false), gate.Register(Guid.NewGuid(), now.AddMilliseconds(20), soundEnabled: false));
    }
}
