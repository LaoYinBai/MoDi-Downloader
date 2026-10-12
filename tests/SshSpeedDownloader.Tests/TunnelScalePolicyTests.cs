using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Tests;

public sealed class TunnelScalePolicyTests
{
    [Fact]
    public void SecondTunnelProbeRequiresHighConcurrencyAndThreePlateauWindows()
    {
        var policy = new TunnelScalePolicy();

        Assert.False(policy.ShouldProbeSecondTunnel(new ThroughputWindow(10_000_000, 200, 0, true), 15, 1));
        Assert.False(policy.ShouldProbeSecondTunnel(new ThroughputWindow(10_000_000, 200, 0, true), 16, 1));
        Assert.False(policy.ShouldProbeSecondTunnel(new ThroughputWindow(10_100_000, 205, 0, true), 16, 1));
        Assert.False(policy.ShouldProbeSecondTunnel(new ThroughputWindow(10_200_000, 210, 0, true), 16, 1));
        Assert.True(policy.ShouldProbeSecondTunnel(new ThroughputWindow(10_250_000, 215, 0, true), 16, 1));
    }

    [Fact]
    public void SecondTunnelIsKeptOnlyWhenItImprovesThroughputByAtLeastFifteenPercent()
    {
        var policy = new TunnelScalePolicy();

        Assert.False(policy.ShouldKeepSecondTunnel(10_000_000, 11_400_000));
        Assert.True(policy.ShouldKeepSecondTunnel(10_000_000, 11_500_000));
        Assert.False(policy.ShouldKeepSecondTunnel(10_000_000, 9_000_000));
    }

    [Fact]
    public void DoesNotProbeSecondTunnelWhenThereIsNoBacklogOrErrorsAreElevated()
    {
        var policy = new TunnelScalePolicy();
        var plateau = new ThroughputWindow(10_000_000, 200, 0, true);
        policy.ShouldProbeSecondTunnel(plateau, 16, 1);
        policy.ShouldProbeSecondTunnel(plateau, 16, 1);

        Assert.False(policy.ShouldProbeSecondTunnel(plateau with { HasBacklog = false }, 16, 1));
        Assert.False(policy.ShouldProbeSecondTunnel(plateau with { ErrorRate = 0.02 }, 16, 1));
    }
}
