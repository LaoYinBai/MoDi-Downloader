namespace SshSpeedDownloader.Core;

public sealed class AsyncConcurrencyGate
{
    private readonly object _sync = new();
    private TaskCompletionSource _changed = NewSignal();
    private int _active;
    private int _limit;

    public AsyncConcurrencyGate(int initialLimit)
    {
        ValidateLimit(initialLimit);
        _limit = initialLimit;
    }

    public int Limit
    {
        get
        {
            lock (_sync)
                return _limit;
        }
    }

    public int ActiveCount
    {
        get
        {
            lock (_sync)
                return _active;
        }
    }

    public void SetLimit(int limit)
    {
        ValidateLimit(limit);
        lock (_sync)
        {
            _limit = limit;
            Pulse();
        }
    }

    public async ValueTask<IDisposable> AcquireAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            Task waitTask;
            lock (_sync)
            {
                if (_active < _limit)
                {
                    _active++;
                    return new Lease(this);
                }
                waitTask = _changed.Task;
            }

            await waitTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private void Release()
    {
        lock (_sync)
        {
            _active--;
            Pulse();
        }
    }

    private void Pulse()
    {
        var current = _changed;
        _changed = NewSignal();
        current.TrySetResult();
    }

    private static TaskCompletionSource NewSignal() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static void ValidateLimit(int limit)
    {
        if (limit is < 1 or > AdaptiveConcurrencyController.MaximumConcurrency)
            throw new ArgumentOutOfRangeException(nameof(limit));
    }

    private sealed class Lease(AsyncConcurrencyGate owner) : IDisposable
    {
        private AsyncConcurrencyGate? _owner = owner;

        public void Dispose() => Interlocked.Exchange(ref _owner, null)?.Release();
    }
}
