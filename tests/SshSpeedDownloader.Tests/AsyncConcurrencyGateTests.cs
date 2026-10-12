using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Tests;

public sealed class AsyncConcurrencyGateTests
{
    [Fact]
    public async Task WaitersStartWhenTheConcurrencyLimitIsRaised()
    {
        var gate = new AsyncConcurrencyGate(1);
        using var first = await gate.AcquireAsync(CancellationToken.None);
        var secondTask = gate.AcquireAsync(CancellationToken.None).AsTask();

        Assert.False(secondTask.IsCompleted);
        gate.SetLimit(2);
        using var second = await secondTask.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(2, gate.ActiveCount);
    }

    [Fact]
    public async Task LoweringTheLimitDoesNotCancelActiveRequestsAndStopsNewOnes()
    {
        var gate = new AsyncConcurrencyGate(2);
        using var first = await gate.AcquireAsync(CancellationToken.None);
        using var second = await gate.AcquireAsync(CancellationToken.None);
        gate.SetLimit(1);
        var waiting = gate.AcquireAsync(CancellationToken.None).AsTask();

        Assert.False(waiting.IsCompleted);
        second.Dispose();
        Assert.False(waiting.IsCompleted);
        first.Dispose();
        using var third = await waiting.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(1, gate.Limit);
        Assert.Equal(1, gate.ActiveCount);
    }
}
