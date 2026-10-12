namespace SshSpeedDownloader.Core;

public static class RangePartition
{
    public const int MaximumRangeCount = 1_000_000;

    public static IReadOnlyList<DownloadRange> Create(long totalLength, long chunkSize)
    {
        var count = Count(totalLength, chunkSize);
        var ranges = new DownloadRange[count];
        for (var index = 0; index < count; index++)
            ranges[index] = Get(totalLength, chunkSize, index);

        return ranges;
    }

    public static int Count(long totalLength, long chunkSize)
    {
        if (totalLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(totalLength));
        if (chunkSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(chunkSize));
        var count = checked(((totalLength - 1) / chunkSize) + 1);
        if (count > MaximumRangeCount)
            throw new ArgumentOutOfRangeException(nameof(chunkSize), "Resource requires too many tracked ranges.");
        return (int)count;
    }

    public static DownloadRange Get(long totalLength, long chunkSize, int index)
    {
        var count = Count(totalLength, chunkSize);
        if ((uint)index >= (uint)count)
            throw new ArgumentOutOfRangeException(nameof(index));
        var offset = checked((long)index * chunkSize);
        return new DownloadRange(index, offset, Math.Min(chunkSize, totalLength - offset));
    }
}
