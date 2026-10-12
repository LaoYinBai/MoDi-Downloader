namespace SshSpeedDownloader.Core;

public readonly record struct ThroughputWindow(
    double BytesPerSecond,
    double P95LatencyMilliseconds,
    double ErrorRate,
    bool HasBacklog);

public sealed class AdaptiveConcurrencyController
{
    public const int MinimumConcurrency = 1;
    public const int MaximumConcurrency = 64;

    private ThroughputWindow? _previous;

    public AdaptiveConcurrencyController(int initialConcurrency = 8)
    {
        if (initialConcurrency is < MinimumConcurrency or > MaximumConcurrency)
            throw new ArgumentOutOfRangeException(nameof(initialConcurrency));
        Current = initialConcurrency;
    }

    public int Current { get; private set; }

    public int Observe(ThroughputWindow window)
    {
        if (!window.HasBacklog || !double.IsFinite(window.BytesPerSecond) || window.BytesPerSecond <= 0 ||
            !double.IsFinite(window.P95LatencyMilliseconds) || window.P95LatencyMilliseconds < 0 ||
            !double.IsFinite(window.ErrorRate) || window.ErrorRate is < 0 or > 1)
        {
            _previous = null;
            return Current;
        }

        if (_previous is not { } previous)
        {
            _previous = window;
            return Current;
        }

        _previous = window;
        if (window.ErrorRate >= 0.03 ||
            (window.P95LatencyMilliseconds > previous.P95LatencyMilliseconds * 1.35 &&
             window.BytesPerSecond <= previous.BytesPerSecond * 1.05))
        {
            Current = Math.Max(MinimumConcurrency, Current - Math.Max(1, (int)Math.Ceiling(Current * 0.25)));
            return Current;
        }

        if (window.BytesPerSecond >= previous.BytesPerSecond * 1.08 &&
            window.ErrorRate <= 0.01 &&
            window.P95LatencyMilliseconds <= Math.Max(1, previous.P95LatencyMilliseconds) * 1.30)
        {
            Current = Math.Min(MaximumConcurrency, Current + Math.Max(1, (int)Math.Ceiling(Current * 0.25)));
            return Current;
        }

        if (window.BytesPerSecond <= previous.BytesPerSecond * 0.92 &&
            window.P95LatencyMilliseconds > previous.P95LatencyMilliseconds * 1.20)
            Current = Math.Max(MinimumConcurrency, Current - Math.Max(1, (int)Math.Ceiling(Current * 0.20)));

        return Current;
    }
}
