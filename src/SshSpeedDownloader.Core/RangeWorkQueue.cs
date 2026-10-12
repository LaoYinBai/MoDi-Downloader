using System.Collections.Concurrent;

namespace SshSpeedDownloader.Core;

public sealed class RangeWorkQueue
{
    private readonly ConcurrentQueue<DownloadRange>? _ranges;
    private readonly long _totalLength;
    private readonly long _chunkSize;
    private readonly int _rangeCount;
    private readonly HashSet<int>? _completed;
    private long _nextIndex;
    private long _remainingCount;

    public RangeWorkQueue(IEnumerable<DownloadRange> ranges)
    {
        ArgumentNullException.ThrowIfNull(ranges);
        _ranges = new ConcurrentQueue<DownloadRange>(ranges);
        _remainingCount = _ranges.Count;
    }

    public RangeWorkQueue(long totalLength, long chunkSize, IEnumerable<int>? completedIndexes = null)
    {
        _totalLength = totalLength;
        _chunkSize = chunkSize;
        _rangeCount = RangePartition.Count(totalLength, chunkSize);
        _completed = completedIndexes is null ? [] : completedIndexes.ToHashSet();
        _remainingCount = _rangeCount - _completed.Count(index => (uint)index < (uint)_rangeCount);
    }

    public bool TryTake(out DownloadRange range)
    {
        if (_ranges is not null)
        {
            if (_ranges.TryDequeue(out range))
            {
                Interlocked.Decrement(ref _remainingCount);
                return true;
            }

            range = default;
            return false;
        }

        while (true)
        {
            var index = Interlocked.Increment(ref _nextIndex) - 1;
            if (index >= _rangeCount)
            {
                range = default;
                return false;
            }

            if (_completed!.Contains((int)index))
                continue;

            Interlocked.Decrement(ref _remainingCount);
            range = RangePartition.Get(_totalLength, _chunkSize, (int)index);
            return true;
        }
    }

    public int RemainingCount => (int)Math.Clamp(Interlocked.Read(ref _remainingCount), 0, int.MaxValue);
}
