namespace SshSpeedDownloader.Core;

public sealed class TunnelScalePolicy
{
    public const int MaximumTunnelCount = 2;

    private ThroughputWindow? _previous;
    private int _plateauWindows;
    private bool _secondTunnelAttempted;

    public bool ShouldProbeSecondTunnel(ThroughputWindow window, int concurrency, int tunnelCount)
    {
        if (_secondTunnelAttempted || tunnelCount >= MaximumTunnelCount)
            return false;

        if (!window.HasBacklog || concurrency < 16 || window.ErrorRate > 0.01 ||
            !double.IsFinite(window.BytesPerSecond) || window.BytesPerSecond <= 0 ||
            !double.IsFinite(window.P95LatencyMilliseconds) || window.P95LatencyMilliseconds < 0)
        {
            _previous = null;
            _plateauWindows = 0;
            return false;
        }

        if (_previous is not { } previous)
        {
            _previous = window;
            return false;
        }

        if (window.BytesPerSecond <= previous.BytesPerSecond * 1.05 &&
            window.P95LatencyMilliseconds >= previous.P95LatencyMilliseconds * 0.90)
            _plateauWindows++;
        else
            _plateauWindows = 0;

        _previous = window;
        if (_plateauWindows < 3)
            return false;

        _secondTunnelAttempted = true;
        return true;
    }

    public bool ShouldKeepSecondTunnel(double singleTunnelBytesPerSecond, double dualTunnelBytesPerSecond) =>
        double.IsFinite(singleTunnelBytesPerSecond) &&
        double.IsFinite(dualTunnelBytesPerSecond) &&
        singleTunnelBytesPerSecond > 0 &&
        dualTunnelBytesPerSecond >= singleTunnelBytesPerSecond * 1.15;
}
