using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Tests;

public sealed class RangeAndResumeTests
{
    [Fact]
    public void RangePartitionCoversTheResourceExactlyOnceWithATailChunk()
    {
        var ranges = RangePartition.Create(10, 4);

        Assert.Collection(
            ranges,
            range => Assert.Equal(new DownloadRange(0, 0, 4), range),
            range => Assert.Equal(new DownloadRange(1, 4, 4), range),
            range => Assert.Equal(new DownloadRange(2, 8, 2), range));
        Assert.Equal(10, ranges.Sum(range => range.Length));
        Assert.Equal(ranges.Count, ranges.Select(range => range.Index).Distinct().Count());
    }

    [Fact]
    public void WorkQueueHandsEachSmallRangeToOnlyOneWorker()
    {
        var queue = new RangeWorkQueue(RangePartition.Create(1_000, 50));
        var issued = new System.Collections.Concurrent.ConcurrentBag<DownloadRange>();

        Parallel.For(0, 16, _ =>
        {
            while (queue.TryTake(out var range))
                issued.Add(range);
        });

        Assert.Equal(20, issued.Count);
        Assert.Equal(20, issued.Select(range => range.Index).Distinct().Count());
        Assert.Equal(1_000, issued.Sum(range => range.Length));
    }

    [Fact]
    public void LazyWorkQueueSkipsPersistedChunksAndKeepsOnlyTheCursor()
    {
        var queue = new RangeWorkQueue(250, 100, [1]);

        Assert.Equal(2, queue.RemainingCount);
        Assert.True(queue.TryTake(out var first));
        Assert.Equal(new DownloadRange(0, 0, 100), first);
        Assert.Equal(1, queue.RemainingCount);
        Assert.True(queue.TryTake(out var tail));
        Assert.Equal(new DownloadRange(2, 200, 50), tail);
        Assert.Equal(0, queue.RemainingCount);
        Assert.False(queue.TryTake(out _));
    }

    [Fact]
    public void LazyWorkQueueIssuesLargePlansUniquelyAcrossManyWorkers()
    {
        const long size = 10_000_000;
        const long chunk = 10_000;
        var queue = new RangeWorkQueue(size, chunk);
        var issued = new System.Collections.Concurrent.ConcurrentBag<DownloadRange>();

        Parallel.For(0, 64, _ =>
        {
            while (queue.TryTake(out var range))
                issued.Add(range);
        });

        Assert.Equal(size / chunk, issued.Count);
        Assert.Equal(issued.Count, issued.Select(range => range.Index).Distinct().Count());
        Assert.Equal(size, issued.Sum(range => range.Length));
        Assert.Equal(0, queue.RemainingCount);
    }

    [Fact]
    public void RejectsPlansThatWouldExceedTheBoundedResumeIndex()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => RangePartition.Count(1_000_001, 1));
    }

    [Fact]
    public void ResumeRequiresMatchingLengthAndAStableValidator()
    {
        var previous = new ResourceIdentity(1_048_576, true, "\"v1\"", null);
        var same = new ResourceIdentity(1_048_576, true, "\"v1\"", null);
        var changedTag = new ResourceIdentity(1_048_576, true, "\"v2\"", null);
        var changedLength = new ResourceIdentity(1_048_577, true, "\"v1\"", null);

        Assert.True(ResumeValidator.CanResume(previous, same));
        Assert.False(ResumeValidator.CanResume(previous, changedTag));
        Assert.False(ResumeValidator.CanResume(previous, changedLength));
        Assert.False(ResumeValidator.CanResume(previous with { AcceptsRanges = false }, same));
    }

    [Fact]
    public void ResumeUsesLastModifiedWhenThereIsNoStrongEntityTag()
    {
        var modified = DateTimeOffset.Parse("2026-10-11T12:00:00Z");
        var previous = new ResourceIdentity(100, true, "W/\"v1\"", modified);
        var same = new ResourceIdentity(100, true, "W/\"v2\"", modified);

        Assert.True(ResumeValidator.CanResume(previous, same));
        Assert.False(ResumeValidator.CanResume(previous, same with { LastModifiedUtc = modified.AddSeconds(1) }));
        Assert.False(ResumeValidator.CanResume(previous with { LastModifiedUtc = null }, same with { LastModifiedUtc = null }));
    }
}
