using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Tests;

public sealed class AdaptiveConcurrencyTests
{
    [Fact]
    public void StartsAtEightAndGrowsConservativelyAfterMeasuredGain()
    {
        var tuner = new AdaptiveConcurrencyController();

        Assert.Equal(8, tuner.Current);
        Assert.Equal(8, tuner.Observe(new ThroughputWindow(1_000_000, 150, 0.0, true)));
        Assert.Equal(10, tuner.Observe(new ThroughputWindow(1_150_000, 155, 0.0, true)));
    }

    [Fact]
    public void BacksOffWhenErrorsAndLatencyRiseWithoutThroughputGain()
    {
        var tuner = new AdaptiveConcurrencyController(initialConcurrency: 8);
        tuner.Observe(new ThroughputWindow(1_000_000, 150, 0.0, true));

        Assert.Equal(6, tuner.Observe(new ThroughputWindow(980_000, 240, 0.05, true)));
    }

    [Fact]
    public void NeverTunesWithoutBacklogAndClampsToConfiguredBounds()
    {
        var tuner = new AdaptiveConcurrencyController(initialConcurrency: 63);
        tuner.Observe(new ThroughputWindow(1_000_000, 150, 0.0, true));

        Assert.Equal(63, tuner.Observe(new ThroughputWindow(1_500_000, 140, 0.0, false)));
        Assert.Equal(63, tuner.Observe(new ThroughputWindow(1_500_000, 140, 0.0, true)));
        Assert.Equal(63, tuner.Observe(new ThroughputWindow(1_500_000, 140, 0.0, true)));
        Assert.Equal(64, tuner.Observe(new ThroughputWindow(2_000_000, 140, 0.0, true)));
    }

    [Fact]
    public void RestartsTheComparisonBaselineAfterAWindowWithoutBacklog()
    {
        var tuner = new AdaptiveConcurrencyController();
        tuner.Observe(new ThroughputWindow(1_000_000, 150, 0.0, true));

        Assert.Equal(8, tuner.Observe(new ThroughputWindow(0, 0, 0, false)));
        Assert.Equal(8, tuner.Observe(new ThroughputWindow(1_500_000, 150, 0.0, true)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65)]
    public void RejectsConcurrencyOutsideTheSafeRange(int concurrency)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new AdaptiveConcurrencyController(concurrency));
    }
}
