using System.Net;
using System.Net.Http;
using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Transport;

public sealed class SshTunnelManager : ITunneledHttpClientPool, IAsyncDisposable
{
    private static readonly TimeSpan[] ReconnectDelays =
    [
        TimeSpan.Zero,
        TimeSpan.FromSeconds(2),
        TimeSpan.FromSeconds(4),
        TimeSpan.FromSeconds(8),
        TimeSpan.FromSeconds(15),
        TimeSpan.FromSeconds(30)
    ];

    private readonly SemaphoreSlim _lifecycle = new(1, 1);
    private readonly object _stateLock = new();
    private readonly List<SshTunnelConnection> _connections = [];
    private readonly Dictionary<Guid, int> _inFlight = [];
    private readonly WindowsCredentialVault _vault = new();
    private SshConnectionProfile? _profile;
    private char[]? _passphrase;
    private CancellationTokenSource? _monitorCts;
    private Task? _monitorTask;
    private bool _userDisconnected;
    private bool _keepSecondary;
    private TunnelStatus _status = new(TunnelState.Disconnected, "未连接", 0, 0);

    public event EventHandler<TunnelStatus>? StatusChanged;

    public TunnelStatus Status
    {
        get
        {
            lock (_stateLock)
                return _status;
        }
    }

    public int TunnelCount
    {
        get
        {
            lock (_stateLock)
                return _connections.Count(connection => connection.IsConnected);
        }
    }

    public bool IsConnected => TunnelCount > 0;

    public async Task ConnectAsync(
        SshConnectionProfile profile,
        string passphrase,
        bool rememberPassphrase,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (!SshConnectionProfileValidator.TryValidate(profile, out var error))
            throw new ArgumentException(error, nameof(profile));
        if (profile.PrivateKeyStreamProvider is null && !File.Exists(profile.PrivateKeyPath))
            throw new FileNotFoundException("所选私钥文件不存在。", profile.PrivateKeyPath);

        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await StopMonitorNoLockAsync().ConfigureAwait(false);
            await DisposeConnectionsNoLockAsync().ConfigureAwait(false);
            _userDisconnected = false;
            _profile = profile;
            ClearPassphrase();

            var credentialName = WindowsCredentialVault.GetTargetName(profile);
            if (rememberPassphrase)
            {
                if (string.IsNullOrEmpty(passphrase))
                {
                    _passphrase = _vault.TryReadPassphrase(credentialName) ?? [];
                }
                else
                    _passphrase = passphrase.ToCharArray();
            }
            else
            {
                _passphrase = passphrase.ToCharArray();
                _vault.ForgetPassphrase(credentialName);
            }

            SetStatus(new TunnelStatus(TunnelState.Connecting, "正在建立安全 SSH 隧道…", 0, 0));
            var primary = await OpenTunnelNoLockAsync(profile, new string(_passphrase), cancellationToken).ConfigureAwait(false);
            AddConnection(primary);
            if (rememberPassphrase && _passphrase.Length > 0)
                _vault.SavePassphrase(credentialName, _passphrase);
            StartMonitor();
            SetStatus(new TunnelStatus(
                TunnelState.Connected,
                "SSH 隧道已连接，下载将强制经云端出口。",
                1,
                primary.SocksPort));
        }
        catch (HostKeyTrustRequiredException exception)
        {
            await DisposeConnectionsNoLockAsync().ConfigureAwait(false);
            ClearPassphrase();
            SetStatus(new TunnelStatus(
                TunnelState.HostKeyTrustRequired,
                exception.ChangedExistingPin ? "服务器主机指纹已变化，连接已阻止。" : "请核对并信任服务器主机指纹。",
                0,
                0,
                exception.Fingerprint));
            throw;
        }
        catch
        {
            await DisposeConnectionsNoLockAsync().ConfigureAwait(false);
            ClearPassphrase();
            SetStatus(new TunnelStatus(TunnelState.Failed, "SSH 连接失败。请检查主机、端口、用户名、密钥和网络。", 0, 0));
            throw;
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    public async Task<ConnectionDiagnostic> TestConnectionAsync(CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(12));
        var diagnosticToken = timeout.Token;
        SshTunnelConnection primary;
        SshConnectionProfile profile;
        lock (_stateLock)
        {
            primary = _connections.FirstOrDefault(connection => connection.IsConnected)
                ?? throw new TunnelUnavailableException("尚未建立 SSH 隧道。");
            profile = _profile ?? throw new TunnelUnavailableException("SSH 身份已清除。");
        }

        var identityTask = profile.SupportsRemoteCommandDiagnostics
            ? primary.ReadServerIdentityAsync(diagnosticToken)
            : Task.FromResult("受限 SSH 转发");
        using var lease = AcquireHttpClient();
        using var response = await lease.HttpClient.GetAsync(
            "https://www.cloudflare.com/cdn-cgi/trace",
            HttpCompletionOption.ResponseHeadersRead,
            diagnosticToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadAsStringAsync(diagnosticToken).ConfigureAwait(false);
        var ipLine = body.Split('\n').FirstOrDefault(line => line.StartsWith("ip=", StringComparison.Ordinal));
        var address = ipLine is null ? null : ipLine[3..].Trim();
        if (address is null || !IPAddress.TryParse(address, out var egressIp))
            throw new IOException("SSH 已连接，但无法从代理出口验证公网地址。");

        var identity = await identityTask.ConfigureAwait(false);
        return new ConnectionDiagnostic(identity, egressIp.ToString(), TunnelCount);
    }

    public ITunneledHttpClientLease AcquireHttpClient()
    {
        lock (_stateLock)
        {
            var connection = _connections
                .Where(candidate => candidate.IsConnected)
                .OrderBy(candidate => _inFlight.GetValueOrDefault(candidate.Id))
                .FirstOrDefault();
            if (connection is null)
                throw new TunnelUnavailableException("SSH 隧道未连接，已阻止本地直连。");

            _inFlight[connection.Id] = _inFlight.GetValueOrDefault(connection.Id) + 1;
            return new TunnelClientLease(
                connection.Id,
                connection.HttpClient,
                () => Release(connection.Id));
        }
    }

    public async Task WaitUntilConnectedAsync(CancellationToken cancellationToken)
    {
        while (!IsConnected)
            await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> TryAddSecondTunnelAsync(CancellationToken cancellationToken)
    {
        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_connections.Count != 1 || _profile is null || _passphrase is null)
                return false;

            SshTunnelConnection second;
            try
            {
                second = await OpenTunnelNoLockAsync(
                    _profile,
                    new string(_passphrase),
                    cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                return false;
            }

            _keepSecondary = true;
            AddConnection(second);
            SetStatus(new TunnelStatus(
                TunnelState.Connected,
                "正在以两条独立 SSH 隧道参与吞吐对比。",
                2,
                _connections[0].SocksPort));
            return true;
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    public async Task RemoveSecondTunnelAsync()
    {
        await _lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_connections.Count < 2)
                return;

            var secondary = _connections[1];
            _connections.RemoveAt(1);
            secondary.ConnectionFaulted -= Connection_ConnectionFaulted;
            _inFlight.Remove(secondary.Id);
            await secondary.DisposeAsync().ConfigureAwait(false);
            _keepSecondary = false;
            SetStatus(new TunnelStatus(
                TunnelState.Connected,
                "已保留单条 SSH 隧道。",
                1,
                _connections[0].SocksPort));
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    public async Task DisconnectAsync()
    {
        _userDisconnected = true;
        _monitorCts?.Cancel();
        await _lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_monitorTask is not null)
            {
                try
                {
                    await _monitorTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
                _monitorTask = null;
            }

            await DisposeConnectionsNoLockAsync().ConfigureAwait(false);
            _monitorCts?.Dispose();
            _monitorCts = null;
            _profile = null;
            ClearPassphrase();
            _keepSecondary = false;
            SetStatus(new TunnelStatus(TunnelState.Disconnected, "已断开。", 0, 0));
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await DisconnectAsync().ConfigureAwait(false);
        _lifecycle.Dispose();
    }

    private async Task<SshTunnelConnection> OpenTunnelNoLockAsync(
        SshConnectionProfile profile,
        string passphrase,
        CancellationToken cancellationToken)
    {
        var connection = await SshTunnelConnection.OpenAsync(profile, passphrase, cancellationToken).ConfigureAwait(false);
        connection.ConnectionFaulted += Connection_ConnectionFaulted;
        return connection;
    }

    private void AddConnection(SshTunnelConnection connection)
    {
        lock (_stateLock)
        {
            _connections.Add(connection);
            _inFlight[connection.Id] = 0;
        }
    }

    private void Release(Guid connectionId)
    {
        lock (_stateLock)
        {
            if (_inFlight.TryGetValue(connectionId, out var count))
                _inFlight[connectionId] = Math.Max(0, count - 1);
        }
    }

    private void Connection_ConnectionFaulted(object? sender, EventArgs args)
    {
        if (_userDisconnected)
            return;

        var activeCount = TunnelCount;
        if (activeCount == 0)
            SetStatus(new TunnelStatus(TunnelState.Reconnecting, "SSH 隧道中断，正在恢复…", 0, 0));
    }

    private void StartMonitor()
    {
        _monitorCts?.Cancel();
        _monitorCts?.Dispose();
        _monitorCts = new CancellationTokenSource();
        _monitorTask = MonitorAsync(_monitorCts.Token);
    }

    private async Task StopMonitorNoLockAsync()
    {
        var cancellation = _monitorCts;
        var monitor = _monitorTask;
        _monitorCts = null;
        _monitorTask = null;
        cancellation?.Cancel();
        if (monitor is not null)
        {
            try
            {
                await monitor.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }
        cancellation?.Dispose();
    }

    private async Task MonitorAsync(CancellationToken cancellationToken)
    {
        var delayIndex = 0;
        while (!cancellationToken.IsCancellationRequested && !_userDisconnected)
        {
            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
            if (TunnelCount > 0)
            {
                delayIndex = 0;
                if (HasStaleConnection())
                    await RepairSecondaryNoLockAsync(cancellationToken).ConfigureAwait(false);
                continue;
            }

            SetStatus(new TunnelStatus(TunnelState.Reconnecting, "SSH 隧道中断，正在恢复…", 0, 0));
            await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_userDisconnected || _profile is null || _passphrase is null)
                    return;

                await DisposeConnectionsNoLockAsync().ConfigureAwait(false);
                try
                {
                    if (delayIndex > 0)
                        await Task.Delay(ReconnectDelays[Math.Min(delayIndex, ReconnectDelays.Length - 1)], cancellationToken)
                            .ConfigureAwait(false);

                    var primary = await OpenTunnelNoLockAsync(
                        _profile,
                        new string(_passphrase),
                        cancellationToken).ConfigureAwait(false);
                    AddConnection(primary);
                    if (_keepSecondary)
                    {
                        try
                        {
                            var secondary = await OpenTunnelNoLockAsync(
                                _profile,
                                new string(_passphrase),
                                cancellationToken).ConfigureAwait(false);
                            AddConnection(secondary);
                        }
                        catch
                        {
                            _keepSecondary = false;
                        }
                    }

                    delayIndex = 0;
                    SetStatus(new TunnelStatus(
                        TunnelState.Connected,
                        "SSH 隧道已恢复，下载正在从已完成分片继续。",
                        TunnelCount,
                        primary.SocksPort));
                }
                catch (HostKeyTrustRequiredException exception)
                {
                    SetStatus(new TunnelStatus(
                        TunnelState.HostKeyTrustRequired,
                        "服务器主机指纹发生变化，自动重连已停止。",
                        0,
                        0,
                        exception.Fingerprint));
                    return;
                }
                catch
                {
                    delayIndex = Math.Min(delayIndex + 1, ReconnectDelays.Length - 1);
                    SetStatus(new TunnelStatus(TunnelState.Reconnecting, "重连暂未成功，将按退避间隔重试。", 0, 0));
                }
            }
            finally
            {
                _lifecycle.Release();
            }
        }
    }

    private bool HasStaleConnection()
    {
        lock (_stateLock)
            return _connections.Any(connection => !connection.IsConnected);
    }

    private async Task RepairSecondaryNoLockAsync(CancellationToken cancellationToken)
    {
        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_userDisconnected)
                return;

            SshTunnelConnection[] stale;
            lock (_stateLock)
            {
                stale = _connections.Where(connection => !connection.IsConnected).ToArray();
                foreach (var connection in stale)
                {
                    _connections.Remove(connection);
                    _inFlight.Remove(connection.Id);
                }
            }

            foreach (var connection in stale)
            {
                connection.ConnectionFaulted -= Connection_ConnectionFaulted;
                await connection.DisposeAsync().ConfigureAwait(false);
            }

            if (_connections.Count == 0)
                return;

            if (_keepSecondary && _connections.Count == 1 && _profile is not null && _passphrase is not null)
            {
                try
                {
                    var second = await OpenTunnelNoLockAsync(
                        _profile,
                        new string(_passphrase),
                        cancellationToken).ConfigureAwait(false);
                    AddConnection(second);
                }
                catch
                {
                    _keepSecondary = false;
                }
            }

            var active = _connections.First(connection => connection.IsConnected);
            SetStatus(new TunnelStatus(
                TunnelState.Connected,
                _connections.Count > 1 ? "双隧道连接已恢复。" : "主 SSH 隧道正常，继续通过云端出口传输。",
                TunnelCount,
                active.SocksPort));
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    private async Task DisposeConnectionsNoLockAsync()
    {
        SshTunnelConnection[] stale;
        lock (_stateLock)
        {
            stale = _connections.ToArray();
            _connections.Clear();
            _inFlight.Clear();
        }

        foreach (var connection in stale)
        {
            connection.ConnectionFaulted -= Connection_ConnectionFaulted;
            await connection.DisposeAsync().ConfigureAwait(false);
        }
    }

    private void ClearPassphrase()
    {
        var secret = _passphrase;
        _passphrase = null;
        if (secret is not null)
            Array.Clear(secret);
    }

    private void SetStatus(TunnelStatus status)
    {
        lock (_stateLock)
            _status = status;
        StatusChanged?.Invoke(this, status);
    }
}
