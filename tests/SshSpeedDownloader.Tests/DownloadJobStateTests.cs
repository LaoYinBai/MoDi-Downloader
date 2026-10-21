using SshSpeedDownloader.Core;
using SshSpeedDownloader.Transport;

namespace SshSpeedDownloader.Tests;

public sealed class DownloadJobStateTests
{
    [Fact]
    public async Task ActiveTransferStillReportsRealRateAndRemainingTime()
    {
        var job = new DownloadJobState(new DownloadRequest(
            new Uri("https://example.test/payload.bin"), Path.GetTempPath()));
        job.SetRangeMetadata(new ResourceIdentity(131_072, false, null, null), 0);
        job.SetStatus(DownloadTaskStatus.Downloading);
        job.CreateSnapshot();
        await Task.Delay(250);
        job.RecordBytes(null, 65_536);

        var snapshot = job.CreateSnapshot();

        Assert.True(snapshot.BytesPerSecond > 0);
        Assert.NotNull(snapshot.RemainingTime);
    }

    [Theory]
    [InlineData(DownloadTaskStatus.Completed)]
    [InlineData(DownloadTaskStatus.Paused)]
    [InlineData(DownloadTaskStatus.Failed)]
    [InlineData(DownloadTaskStatus.Cancelled)]
    [InlineData(DownloadTaskStatus.ResourceChanged)]
    [InlineData(DownloadTaskStatus.Reconnecting)]
    public async Task InactiveSnapshotNeverReportsStaleSpeed(DownloadTaskStatus status)
    {
        var job = new DownloadJobState(new DownloadRequest(
            new Uri("https://example.test/payload.bin"), Path.GetTempPath()));
        job.SetStatus(DownloadTaskStatus.Downloading);
        job.CreateSnapshot();
        await Task.Delay(250);
        job.RecordBytes(null, 65_536);
        job.SetStatus(status);

        var snapshot = job.CreateSnapshot();

        Assert.Equal(0, snapshot.BytesPerSecond);
        Assert.Null(snapshot.RemainingTime);
    }
}
