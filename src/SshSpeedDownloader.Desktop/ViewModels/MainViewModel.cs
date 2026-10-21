using System.Collections.ObjectModel;
using System.Diagnostics;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SshSpeedDownloader.Core;
using SshSpeedDownloader.Desktop.Models;
using SshSpeedDownloader.Desktop.Services;
using SshSpeedDownloader.Transport;
using SshSpeedDownloader.Transport.IdentityProviders;

namespace SshSpeedDownloader.Desktop.ViewModels;

public partial class MainViewModel : ViewModelBase
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

    private readonly SshTunnelManager _tunnels;
    private readonly DownloadManager _downloads;
    private readonly DesktopSettingsStore _settingsStore;
    private readonly WindowsCredentialVault _credentialStore;
    private readonly WindowsCompletionFeedbackService _completionFeedback;
    private readonly string _settingsRoot;
    private string? _systemDownloadsDirectory;
    private IConnectionIdentityProvider? _identityProvider;
    private IPrivateIdentityProvisioner? _identityProvisioner;
    private ICloudAuthorizationWorkflow? _cloudAuthorizationWorkflow;
    private WindowsDeviceIdentityStore? _deviceIdentityStore;
    private HttpClient? _authorizationHttpClient;
    private ConnectionIdentityProviderKind _identityProviderKind = ConnectionIdentityProviderKind.PrivateIdentity;
    private CancellationTokenSource? _connectionLoopCancellation;
    private Task? _connectionLoop;
    private CancellationTokenSource? _settingsSaveCancellation;
    private bool _initialized;
    private bool _restoring;
    private bool _shuttingDown;
    private bool _loadingSettings;

    [ObservableProperty] private string _downloadUrl = "";
    [ObservableProperty] private string _taskDownloadDirectory = "";
    [ObservableProperty] private string _defaultDownloadDirectory = "";
    [ObservableProperty] private bool _hasCustomDefaultDownloadDirectory;
    [ObservableProperty] private bool _defaultDirectoryWritable;
    [ObservableProperty] private bool _taskDirectoryWritable;
    [ObservableProperty] private int _selectedConcurrency = 8;
    [ObservableProperty] private bool _autoTuneConcurrency = true;
    [ObservableProperty] private bool _completionSoundEnabled = true;
    [ObservableProperty] private int _completionVolumePercent = 55;
    [ObservableProperty] private string _unlockPassphrase = "";
    [ObservableProperty] private bool _needsCredentialSetup;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _statusMessage = "正在准备云端连接。";
    [ObservableProperty] private string _connectionDetail = "";
    [ObservableProperty] private string _directoryMessage = "";
    [ObservableProperty] private string _identitySourceMessage = "";
    [ObservableProperty] private string _deviceIdentityText = "";
    [ObservableProperty] private string _authorizationStatusText = "";
    [ObservableProperty] private DeviceApprovalStatus? _accessRequestStatus;
    [ObservableProperty] private TunnelStatus _tunnelStatus;
    [ObservableProperty] private double _totalBytesPerSecond;
    [ObservableProperty] private int _activeTaskCount;
    [ObservableProperty] private int _activeConnectionCount;
    [ObservableProperty] private double _totalProgress;
    [ObservableProperty] private string _totalProgressText = "没有进行中的任务";

    public MainViewModel()
    {
        _settingsRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "MoDiDownloader");
        Directory.CreateDirectory(_settingsRoot);
        _settingsStore = new DesktopSettingsStore(Path.Combine(_settingsRoot, "settings.json"));
        _credentialStore = new WindowsCredentialVault();
        _tunnels = new SshTunnelManager();
        _downloads = new DownloadManager(
            _tunnels,
            new JsonDownloadManifestStore(Path.Combine(_settingsRoot, "tasks")));
        _completionFeedback = new WindowsCompletionFeedbackService();
        _completionFeedback.NotificationActivated += CompletionFeedback_NotificationActivated;
        _tunnelStatus = _tunnels.Status;
        _downloads.SnapshotChanged += Downloads_SnapshotChanged;
        _tunnels.StatusChanged += Tunnels_StatusChanged;

        try
        {
            _systemDownloadsDirectory = WindowsKnownFolders.GetDownloadsPath();
            DefaultDownloadDirectory = _systemDownloadsDirectory;
            TaskDownloadDirectory = _systemDownloadsDirectory;
        }
        catch (Exception exception)
        {
            DirectoryMessage = $"无法解析 Windows 下载文件夹：{SafeExceptionMessage(exception)}";
        }
    }

    public ObservableCollection<DownloadTaskViewModel> Tasks { get; } = [];
    public int[] ConcurrencyChoices { get; } = [1, 2, 4, 8, 16, 32, 64];
    public bool IsConnected => TunnelStatus.State == TunnelState.Connected;
    public string ApplicationVersionText => typeof(MainViewModel).Assembly.GetName().Version?.ToString(3) ?? "unknown";
    public string WindowTitle => $"MoDi Downloader {ApplicationVersionText}";
    public string LocationText => "Aliyun Beijing";
    public string TunnelStatusText => TunnelStatus.State switch
    {
        TunnelState.Connected => "云端已连接",
        TunnelState.Connecting => "正在连接…",
        TunnelState.Reconnecting => "正在重连…",
        TunnelState.HostKeyTrustRequired => "主机指纹校验失败",
        TunnelState.Failed => "连接失败",
        _ => "未连接"
    };
    public string TunnelCountText => $"{TunnelStatus.TunnelCount} 隧道";
    public string TotalSpeedText => $"{TotalBytesPerSecond / (1024d * 1024d):0.00} MiB/s";
    public string ActiveTaskText => $"{ActiveTaskCount} 活跃任务";
    public string ActiveConnectionsText => $"{ActiveConnectionCount} 连接";
    public string HasCustomDirectoryText => HasCustomDefaultDownloadDirectory ? "自定义默认位置" : "系统下载文件夹";
    public string PrivateBuildNotice => IsPrivateBuild ? "私人版 · 内置可提取 SSH 身份材料，仅供本人使用" : "";
    public bool HasTasks => Tasks.Count > 0;
    public bool CanAddDownload => IsConnected && TaskDirectoryWritable;
    public bool IsPrivateBuild => PrivateBuildIdentity.HasEmbeddedIdentity;
    public bool IsCloudEdition => !IsPrivateBuild;
    public bool CanRequestAccess => IsCloudEdition &&
        _cloudAuthorizationWorkflow is not null &&
        !IsBusy &&
        AccessRequestStatus is not (DeviceApprovalStatus.Pending or DeviceApprovalStatus.Approved or DeviceApprovalStatus.Revoked);
    public bool CanRefreshAccessStatus => IsCloudEdition && _cloudAuthorizationWorkflow is not null && !IsBusy;
    public string RequestAccessButtonText => AccessRequestStatus switch
    {
        DeviceApprovalStatus.Pending => "申请待批准",
        DeviceApprovalStatus.Approved => "已获批准",
        DeviceApprovalStatus.Revoked => "授权已撤销",
        DeviceApprovalStatus.Rejected or DeviceApprovalStatus.Expired => "重新申请",
        _ => "申请使用下载器"
    };
    public bool CanRevokeLocalAuthorization => IsPrivateBuild &&
        _identityProvider?.Kind == ConnectionIdentityProviderKind.PrivateIdentity;

    public event EventHandler? ActivateWindowRequested;

    partial void OnIsBusyChanged(bool value)
    {
        OnPropertyChanged(nameof(CanRequestAccess));
        OnPropertyChanged(nameof(CanRefreshAccessStatus));
    }

    partial void OnAccessRequestStatusChanged(DeviceApprovalStatus? value)
    {
        OnPropertyChanged(nameof(CanRequestAccess));
        OnPropertyChanged(nameof(RequestAccessButtonText));
    }

    public async Task InitializeAsync()
    {
        if (_initialized)
            return;

        _loadingSettings = true;
        var settings = await _settingsStore.LoadAsync();
        _identityProviderKind = IsPrivateBuild
            ? ConnectionIdentityProviderKind.PrivateIdentity
            : ConnectionIdentityProviderKind.CloudApproved;
        if (IsPrivateBuild)
        {
            _identityProvider = ConnectionIdentityProviderFactory.Create(
                _identityProviderKind,
                PrivateBuildIdentity.CreateProfile(),
                _credentialStore);
            IdentitySourceMessage = "本机私有身份 · 口令仅保存于 Windows 凭据管理器";
            AuthorizationStatusText = "私人身份连接模式。";
        }
        else
        {
            try
            {
                var identityPath = Path.Combine(_settingsRoot, "device-identity.json");
                _deviceIdentityStore = new WindowsDeviceIdentityStore(identityPath, Environment.MachineName);
                var device = await _deviceIdentityStore.LoadOrCreateAsync();
                _authorizationHttpClient = CloudDeviceAuthorizationClient.CreateHttpClient();
                var cloudClient = new CloudDeviceAuthorizationClient(
                    _authorizationHttpClient,
                    _deviceIdentityStore,
                    CloudAuthorizationConfiguration.CreateDefault());
                _identityProvider = ConnectionIdentityProviderFactory.Create(
                    _identityProviderKind,
                    privateProfile: null,
                    _credentialStore,
                    cloudClient,
                    device);
                _cloudAuthorizationWorkflow = _identityProvider as ICloudAuthorizationWorkflow;
                DeviceIdentityText = $"{device.DisplayName} · {device.DeviceId}";
                IdentitySourceMessage = "共享版设备身份 · 每台设备独立密钥 · 需管理员批准";
                AuthorizationStatusText = "尚未申请使用权限。";
            }
            catch (Exception exception)
            {
                _identityProvider = ConnectionIdentityProviderFactory.Create(
                    _identityProviderKind,
                    privateProfile: null,
                    _credentialStore);
                DeviceIdentityText = "本机设备身份不可用";
                IdentitySourceMessage = "设备密钥初始化失败；未回退到私人 SSH 身份。";
                AuthorizationStatusText = SafeExceptionMessage(exception);
            }
        }
        _identityProvisioner = _identityProvider as IPrivateIdentityProvisioner;
        OnPropertyChanged(nameof(CanRevokeLocalAuthorization));
        OnPropertyChanged(nameof(CanRequestAccess));
        OnPropertyChanged(nameof(CanRefreshAccessStatus));

        HasCustomDefaultDownloadDirectory = settings.HasCustomDefaultDownloadDirectory;
        DefaultDownloadDirectory = settings.HasCustomDefaultDownloadDirectory
            ? settings.DefaultDownloadDirectory
            : _systemDownloadsDirectory ?? "";
        TaskDownloadDirectory = DefaultDownloadDirectory;
        SelectedConcurrency = ConcurrencyChoices.Contains(settings.InitialConcurrency)
            ? settings.InitialConcurrency
            : 8;
        AutoTuneConcurrency = settings.AutoTuneConcurrency;
        CompletionSoundEnabled = settings.CompletionSoundEnabled;
        CompletionVolumePercent = Math.Clamp(settings.CompletionVolumePercent, 0, 100);
        ValidateDefaultDirectory();
        ValidateTaskDirectory();

        Volatile.Write(ref _restoring, true);
        try
        {
            var restored = await _downloads.RestoreAsync();
            foreach (var snapshot in _downloads.GetSnapshots())
            {
                UpsertTask(snapshot);
                if (snapshot.Status == DownloadTaskStatus.Completed)
                    _completionFeedback.MarkHandledWithoutFeedback(snapshot.Id);
            }
            StatusMessage = restored == 0 ? "准备就绪。" : $"已恢复 {restored} 个本地任务。";
        }
        catch (Exception exception)
        {
            StatusMessage = $"任务恢复失败：{SafeExceptionMessage(exception)}";
        }
        finally
        {
            Volatile.Write(ref _restoring, false);
            _loadingSettings = false;
            _initialized = true;
        }

        UpdateTotals();
        StartConnectionLoop(restart: false);
    }

    [RelayCommand]
    private Task ReconnectAsync() => RestartConnectionLoopAsync();

    [RelayCommand]
    private async Task RequestAccessAsync()
    {
        var workflow = _cloudAuthorizationWorkflow;
        if (workflow is null || !CanRequestAccess)
        {
            StatusMessage = "当前构建或设备状态不允许提交新的访问申请。";
            return;
        }

        IsBusy = true;
        try
        {
            var result = await workflow.RequestAccessAsync(CancellationToken.None);
            if (result.Succeeded && result.Value is not null)
            {
                ApplyAccessRequest(result.Value);
                StatusMessage = "访问申请已提交；批准后会自动建立云端连接。";
                StartConnectionLoop(restart: false);
            }
            else
            {
                AuthorizationStatusText = result.UserMessage ?? "申请未能提交；下载器没有切换到本地直连。";
                StatusMessage = AuthorizationStatusText;
            }
        }
        catch (Exception exception)
        {
            AuthorizationStatusText = $"授权服务暂不可用：{SafeExceptionMessage(exception)}";
            StatusMessage = AuthorizationStatusText;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task RefreshApprovalStatusAsync()
    {
        var workflow = _cloudAuthorizationWorkflow;
        if (workflow is null)
        {
            AuthorizationStatusText = "云端设备鉴权服务尚未配置。";
            return;
        }

        IsBusy = true;
        try
        {
            var result = await workflow.RefreshAccessStatusAsync(CancellationToken.None);
            if (result.Succeeded && result.Value is not null)
            {
                ApplyAccessRequest(result.Value);
                if (result.Value.Status == DeviceApprovalStatus.Approved && !IsConnected)
                    StartConnectionLoop(restart: false);
            }
            else
            {
                AuthorizationStatusText = result.UserMessage ?? "无法读取授权状态。";
            }
        }
        catch (Exception exception)
        {
            AuthorizationStatusText = $"授权状态读取失败：{SafeExceptionMessage(exception)}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void ApplyAccessRequest(DeviceAccessRequest request)
    {
        AccessRequestStatus = request.Status;
        AuthorizationStatusText = request.Status switch
        {
            DeviceApprovalStatus.Pending => "申请待批准；批准后会自动连接。",
            DeviceApprovalStatus.Approved => "设备已获批 · 长期授权有效。",
            DeviceApprovalStatus.Rejected => "申请已被拒绝，可重新申请。",
            DeviceApprovalStatus.Expired => "申请已过期，可重新申请。",
            DeviceApprovalStatus.Revoked => "此设备授权已撤销，连接将被关闭。",
            _ => "授权状态未知。"
        };
    }

    [RelayCommand]
    private async Task SaveUnlockPassphraseAsync()
    {
        if (_identityProvisioner is null || string.IsNullOrEmpty(UnlockPassphrase))
        {
            StatusMessage = "私人身份尚未配置，无法保存解锁口令。";
            return;
        }

        IsBusy = true;
        var passphrase = UnlockPassphrase.ToCharArray();
        try
        {
            _identityProvisioner.StorePassphrase(passphrase);
            NeedsCredentialSetup = false;
            StatusMessage = "解锁口令已保存到 Windows 凭据管理器。";
        }
        catch (Exception exception)
        {
            StatusMessage = $"无法保存解锁口令：{SafeExceptionMessage(exception)}";
        }
        finally
        {
            Array.Clear(passphrase);
            UnlockPassphrase = "";
            IsBusy = false;
        }

        if (!NeedsCredentialSetup)
            await RestartConnectionLoopAsync();
    }

    [RelayCommand]
    private void PreviewCompletionSound() => _completionFeedback.Preview(CompletionVolumePercent);

    [RelayCommand]
    private async Task RevokeLocalAuthorizationAsync()
    {
        if (_identityProvider is null)
            return;
        IsBusy = true;
        try
        {
            await StopConnectionLoopAsync();
            await _downloads.PauseAllAsync();
            await _tunnels.DisconnectAsync();
            var result = await _identityProvider.RevokeLocalAuthorizationAsync(CancellationToken.None);
            StatusMessage = result.Succeeded
                ? "本机授权凭据已撤销；服务器端在线连接是否终止由服务端策略决定。"
                : result.UserMessage ?? "无法撤销本机授权。";
            NeedsCredentialSetup = result.Succeeded && _identityProvider.Kind == ConnectionIdentityProviderKind.PrivateIdentity;
        }
        catch (Exception exception)
        {
            StatusMessage = $"撤销本机授权失败：{SafeExceptionMessage(exception)}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task AddDownloadAsync()
    {
        if (!IsConnected)
        {
            StatusMessage = "云端代理尚未连接；下载不会改走本地网络。";
            return;
        }
        if (!UrlSafety.TryValidateDownloadUri(DownloadUrl, out var safeUri))
        {
            StatusMessage = "请输入不含用户名/密码的 HTTP 或 HTTPS 下载链接。";
            return;
        }
        if (!WritableDirectoryProbe.TryCheck(TaskDownloadDirectory, out var directoryError))
        {
            TaskDirectoryWritable = false;
            DirectoryMessage = directoryError;
            OnPropertyChanged(nameof(CanAddDownload));
            return;
        }

        try
        {
            var id = await _downloads.AddAsync(new DownloadRequest(
                safeUri!,
                Path.GetFullPath(TaskDownloadDirectory),
                SelectedConcurrency,
                AutoTuneConcurrency));
            DownloadUrl = "";
            TaskDownloadDirectory = DefaultDownloadDirectory;
            ValidateTaskDirectory();
            StatusMessage = $"已加入队列：{id.ToString("N")[..8]}";
        }
        catch (Exception exception)
        {
            StatusMessage = $"无法添加任务：{SafeExceptionMessage(exception)}";
        }
    }

    [RelayCommand]
    private async Task SetDefaultDirectoryAsync()
    {
        await ApplyDefaultDirectoryAsync(TaskDownloadDirectory);
    }

    public async Task ApplyDefaultDirectoryAsync(string path)
    {
        if (!WritableDirectoryProbe.TryCheck(path, out var error))
        {
            DirectoryMessage = error;
            return;
        }

        DefaultDownloadDirectory = Path.GetFullPath(path);
        TaskDownloadDirectory = DefaultDownloadDirectory;
        HasCustomDefaultDownloadDirectory = true;
        DefaultDirectoryWritable = true;
        TaskDirectoryWritable = true;
        DirectoryMessage = "默认下载目录已更新。已有任务的绝对保存路径不变。";
        await SaveSettingsAsync();
        OnPropertyChanged(nameof(HasCustomDirectoryText));
    }

    [RelayCommand]
    private async Task RestoreSystemDownloadsDirectoryAsync()
    {
        if (string.IsNullOrWhiteSpace(_systemDownloadsDirectory))
        {
            DirectoryMessage = "Windows 未能返回系统下载文件夹位置；未切换到其他目录。";
            return;
        }
        if (!WritableDirectoryProbe.TryCheck(_systemDownloadsDirectory, out var error))
        {
            DirectoryMessage = error;
            return;
        }

        DefaultDownloadDirectory = _systemDownloadsDirectory;
        TaskDownloadDirectory = _systemDownloadsDirectory;
        HasCustomDefaultDownloadDirectory = false;
        DefaultDirectoryWritable = true;
        TaskDirectoryWritable = true;
        DirectoryMessage = "已恢复到 Windows 系统下载文件夹。已有任务的绝对保存路径不变。";
        await SaveSettingsAsync();
        OnPropertyChanged(nameof(HasCustomDirectoryText));
    }

    [RelayCommand]
    private async Task PauseTaskAsync(Guid id)
    {
        try { await _downloads.PauseAsync(id); }
        catch (Exception exception) { StatusMessage = $"暂停失败：{SafeExceptionMessage(exception)}"; }
    }

    [RelayCommand]
    private async Task ResumeTaskAsync(Guid id)
    {
        try { await _downloads.ResumeAsync(id); }
        catch (Exception exception) { StatusMessage = $"继续失败：{SafeExceptionMessage(exception)}"; }
    }

    [RelayCommand]
    private async Task CancelTaskAsync(Guid id)
    {
        try { await _downloads.CancelAsync(id); }
        catch (Exception exception) { StatusMessage = $"取消失败：{SafeExceptionMessage(exception)}"; }
    }

    [RelayCommand]
    private async Task RetryTaskAsync(Guid id)
    {
        try
        {
            var snapshot = _downloads.GetSnapshot(id);
            if (snapshot.Status == DownloadTaskStatus.ResourceChanged)
                await _downloads.RestartAsync(id);
            else
                await _downloads.ResumeAsync(id);
        }
        catch (Exception exception) { StatusMessage = $"重试失败：{SafeExceptionMessage(exception)}"; }
    }

    [RelayCommand]
    private void OpenFile(Guid id)
    {
        try
        {
            var snapshot = _downloads.GetSnapshot(id);
            Process.Start(new ProcessStartInfo(snapshot.TargetPath) { UseShellExecute = true });
        }
        catch (Exception exception) { StatusMessage = $"打开文件失败：{SafeExceptionMessage(exception)}"; }
    }

    [RelayCommand]
    private void OpenFolder(Guid id)
    {
        try
        {
            var snapshot = _downloads.GetSnapshot(id);
            Process.Start(new ProcessStartInfo("explorer.exe")
            {
                UseShellExecute = true,
                ArgumentList = { "/select,", snapshot.TargetPath }
            });
        }
        catch (Exception exception) { StatusMessage = $"打开目录失败：{SafeExceptionMessage(exception)}"; }
    }

    public void SetTaskDownloadDirectory(string path)
    {
        if (!WritableDirectoryProbe.TryCheck(path, out var error))
        {
            TaskDirectoryWritable = false;
            DirectoryMessage = error;
            OnPropertyChanged(nameof(CanAddDownload));
            return;
        }

        TaskDownloadDirectory = Path.GetFullPath(path);
        TaskDirectoryWritable = true;
        DirectoryMessage = "本任务将保存到所选目录。";
        OnPropertyChanged(nameof(CanAddDownload));
    }

    public async Task ShutdownAsync()
    {
        if (_shuttingDown)
            return;
        _shuttingDown = true;
        await StopConnectionLoopAsync();
        _settingsSaveCancellation?.Cancel();
        _settingsSaveCancellation?.Dispose();
        _settingsSaveCancellation = null;
        try
        {
            await SaveSettingsAsync();
            await _downloads.DisposeAsync();
            await _tunnels.DisposeAsync();
            _authorizationHttpClient?.Dispose();
            _authorizationHttpClient = null;
        }
        catch (Exception exception)
        {
            StatusMessage = $"退出清理遇到错误：{SafeExceptionMessage(exception)}";
        }
        finally
        {
            _completionFeedback.NotificationActivated -= CompletionFeedback_NotificationActivated;
            _completionFeedback.Dispose();
        }
    }

    private void StartConnectionLoop(bool restart)
    {
        if (!_initialized || _shuttingDown)
            return;
        if (restart)
        {
            _ = RestartConnectionLoopAsync();
            return;
        }
        if (_connectionLoop is { IsCompleted: false })
            return;

        _connectionLoopCancellation = new CancellationTokenSource();
        var token = _connectionLoopCancellation.Token;
        _connectionLoop = Task.Run(() => ConnectUntilReadyAsync(token), token);
    }

    private async Task RestartConnectionLoopAsync()
    {
        await StopConnectionLoopAsync();
        if (_shuttingDown || !_initialized)
            return;
        try
        {
            await _tunnels.DisconnectAsync().ConfigureAwait(false);
        }
        catch
        {
        }
        StartConnectionLoop(restart: false);
    }

    private async Task StopConnectionLoopAsync()
    {
        var cancellation = _connectionLoopCancellation;
        var task = _connectionLoop;
        _connectionLoopCancellation = null;
        _connectionLoop = null;
        cancellation?.Cancel();
        if (task is not null)
        {
            try { await task.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
            catch { }
        }
        cancellation?.Dispose();
    }

    private async Task ConnectUntilReadyAsync(CancellationToken cancellationToken)
    {
        var provider = _identityProvider;
        if (provider is null)
        {
            SetConnectionMessage("身份提供者尚未初始化。", "");
            return;
        }

        ConnectionIdentityResult? acquisition = null;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                acquisition = await provider.AcquireConnectionIdentityAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                SetConnectionMessage($"身份获取失败：{SafeExceptionMessage(exception)}", "");
                return;
            }

            if (acquisition.AccessRequest is not null)
                QueueAccessRequestUpdate(acquisition.AccessRequest);
            else if (acquisition.State == ConnectionIdentityState.Revoked)
                Dispatcher.UIThread.Post(() =>
                {
                    AccessRequestStatus = DeviceApprovalStatus.Revoked;
                    AuthorizationStatusText = "此设备授权已撤销。";
                });

            if (acquisition.State == ConnectionIdentityState.CredentialRequired)
            {
                SetCredentialSetupRequired(acquisition.UserMessage ?? "需要保存 SSH 私钥口令。");
                return;
            }

            if (acquisition.State == ConnectionIdentityState.Pending ||
                acquisition.State == ConnectionIdentityState.Failed &&
                acquisition.ErrorCode == IdentityProviderErrorCode.NetworkUnavailable &&
                _cloudAuthorizationWorkflow is not null)
            {
                SetConnectionMessage(
                    acquisition.State == ConnectionIdentityState.Pending
                        ? "申请待手机端批准；下载仍保持关闭。"
                        : "暂时无法读取授权状态，稍后重试。",
                    DeviceIdentityText);
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(15), cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                continue;
            }

            if (acquisition.State != ConnectionIdentityState.Ready || acquisition.Identity is null)
            {
                SetConnectionMessage(acquisition.UserMessage ?? "云端身份不可用。", "");
                return;
            }
            break;
        }

        if (cancellationToken.IsCancellationRequested || acquisition?.Identity is not { } connectionIdentity)
            return;

        for (var attempt = 0; !cancellationToken.IsCancellationRequested; attempt++)
        {
            try
            {
                await _tunnels.ConnectAsync(
                    connectionIdentity.SshProfile,
                    passphrase: "",
                    rememberPassphrase: true,
                    cancellationToken).ConfigureAwait(false);
                NeedsCredentialSetup = false;
                try
                {
                    var diagnostic = await _tunnels.TestConnectionAsync(cancellationToken).ConfigureAwait(false);
                    SetConnectionMessage(
                        "云端已连接。",
                        $"{LocationText} · {diagnostic.ServerIdentity} · 出口 {diagnostic.EgressIp}");
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    return;
                }
                catch
                {
                    SetConnectionMessage("SSH 隧道已连接；公网验证端点不可用，下载仍只走云端出口。", LocationText);
                }
                await MonitorCloudAuthorizationAsync(cancellationToken).ConfigureAwait(false);
                return;
            }
            catch (HostKeyTrustRequiredException)
            {
                SetConnectionMessage("服务器主机指纹与本机固定 pin 不匹配；自动连接已停止。", "安全校验失败");
                return;
            }
            catch (PrivateKeyPassphraseRequiredException)
            {
                SetCredentialSetupRequired("私钥需要解锁口令。输入一次后会保存到 Windows 凭据管理器。 ");
                return;
            }
            catch (PrivateKeyUnlockFailedException)
            {
                SetCredentialSetupRequired("凭据管理器中的口令无法解锁私钥；请重新输入并保存。 ");
                return;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                var delay = ReconnectDelays[Math.Min(attempt + 1, ReconnectDelays.Length - 1)];
                SetConnectionMessage(
                    $"连接失败，将在 {Math.Ceiling(delay.TotalSeconds):0} 秒后自动重试：{SafeExceptionMessage(exception)}",
                    LocationText);
                try
                {
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
    }

    private async Task MonitorCloudAuthorizationAsync(CancellationToken cancellationToken)
    {
        var workflow = _cloudAuthorizationWorkflow;
        if (workflow is null)
            return;

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(15), cancellationToken).ConfigureAwait(false);
                var result = await workflow.RefreshAccessStatusAsync(cancellationToken).ConfigureAwait(false);
                if (result.Succeeded && result.Value is not null)
                {
                    QueueAccessRequestUpdate(result.Value);
                    if (result.Value.Status == DeviceApprovalStatus.Approved)
                        continue;

                    await _downloads.PauseAllAsync().ConfigureAwait(false);
                    await _tunnels.DisconnectAsync().ConfigureAwait(false);
                    SetConnectionMessage("授权状态已变更，云端隧道已关闭；下载不会切换到本地网络。", "");
                    return;
                }

                if (result.ErrorCode == IdentityProviderErrorCode.AuthorizationRevoked)
                {
                    await _downloads.PauseAllAsync().ConfigureAwait(false);
                    await _tunnels.DisconnectAsync().ConfigureAwait(false);
                    Dispatcher.UIThread.Post(() =>
                    {
                        AccessRequestStatus = DeviceApprovalStatus.Revoked;
                        AuthorizationStatusText = "此设备授权已撤销。";
                    });
                    SetConnectionMessage("此设备授权已撤销，云端隧道已关闭。", "");
                    return;
                }

                SetConnectionMessage(
                    "暂时无法刷新授权状态；现有流量仍仅通过 SSH 隧道，重连仍需服务端批准。",
                    LocationText);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                SetConnectionMessage(
                    $"授权状态暂不可用：{SafeExceptionMessage(exception)}",
                    LocationText);
            }
        }
    }

    private void QueueAccessRequestUpdate(DeviceAccessRequest request) =>
        Dispatcher.UIThread.Post(() => ApplyAccessRequest(request));

    private async Task SaveSettingsAsync()
    {
        await _settingsStore.SaveAsync(new DesktopSettings
        {
            IdentityProviderKind = _identityProviderKind,
            DefaultDownloadDirectory = DefaultDownloadDirectory,
            HasCustomDefaultDownloadDirectory = HasCustomDefaultDownloadDirectory,
            InitialConcurrency = SelectedConcurrency,
            AutoTuneConcurrency = AutoTuneConcurrency,
            CompletionSoundEnabled = CompletionSoundEnabled,
            CompletionVolumePercent = Math.Clamp(CompletionVolumePercent, 0, 100)
        });
    }

    private void QueueSettingsSave()
    {
        if (!_initialized || _loadingSettings || _shuttingDown)
            return;
        _settingsSaveCancellation?.Cancel();
        _settingsSaveCancellation?.Dispose();
        _settingsSaveCancellation = new CancellationTokenSource();
        var token = _settingsSaveCancellation.Token;
        _ = SaveSettingsSoonAsync(token);
    }

    private async Task SaveSettingsSoonAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMilliseconds(400), cancellationToken).ConfigureAwait(false);
            await SaveSettingsAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception exception)
        {
            Dispatcher.UIThread.Post(() => StatusMessage = $"设置保存失败：{SafeExceptionMessage(exception)}");
        }
    }

    private void ValidateDefaultDirectory()
    {
        DefaultDirectoryWritable = WritableDirectoryProbe.TryCheck(DefaultDownloadDirectory, out var error);
        if (!DefaultDirectoryWritable)
            DirectoryMessage = error;
        OnPropertyChanged(nameof(CanAddDownload));
        OnPropertyChanged(nameof(HasCustomDirectoryText));
    }

    private void ValidateTaskDirectory()
    {
        TaskDirectoryWritable = WritableDirectoryProbe.TryCheck(TaskDownloadDirectory, out var error);
        if (!TaskDirectoryWritable)
            DirectoryMessage = error;
        OnPropertyChanged(nameof(CanAddDownload));
    }

    private void Downloads_SnapshotChanged(object? sender, DownloadTaskSnapshot snapshot)
    {
        if (Volatile.Read(ref _restoring))
        {
            if (snapshot.Status == DownloadTaskStatus.Completed)
                _completionFeedback.MarkHandledWithoutFeedback(snapshot.Id);
            return;
        }

        Dispatcher.UIThread.Post(() =>
        {
            UpsertTask(snapshot);
            UpdateTotals();
            if (snapshot.Status == DownloadTaskStatus.Completed)
                _completionFeedback.NotifyCompleted(
                    snapshot.Id,
                    snapshot.FileName,
                    CompletionSoundEnabled,
                    CompletionVolumePercent);
        });
    }

    private void Tunnels_StatusChanged(object? sender, TunnelStatus status) =>
        Dispatcher.UIThread.Post(() =>
        {
            TunnelStatus = status;
            OnPropertyChanged(nameof(IsConnected));
            OnPropertyChanged(nameof(TunnelStatusText));
            OnPropertyChanged(nameof(TunnelCountText));
            OnPropertyChanged(nameof(CanAddDownload));
        });

    private void CompletionFeedback_NotificationActivated(object? sender, EventArgs e) =>
        Dispatcher.UIThread.Post(() => ActivateWindowRequested?.Invoke(this, EventArgs.Empty));

    private void SetConnectionMessage(string message, string detail) => Dispatcher.UIThread.Post(() =>
    {
        StatusMessage = message;
        ConnectionDetail = detail;
    });

    private void SetCredentialSetupRequired(string message) => Dispatcher.UIThread.Post(() =>
    {
        NeedsCredentialSetup = true;
        StatusMessage = message;
        ConnectionDetail = "口令只保存到 Windows 凭据管理器，不写入设置或下载任务。";
    });

    private void UpsertTask(DownloadTaskSnapshot snapshot)
    {
        var existing = Tasks.FirstOrDefault(task => task.Id == snapshot.Id);
        if (existing is null)
            Tasks.Insert(0, new DownloadTaskViewModel(snapshot));
        else
            existing.Update(snapshot);
        OnPropertyChanged(nameof(HasTasks));
    }

    private void UpdateTotals()
    {
        var snapshots = _downloads.GetSnapshots();
        var active = snapshots.Where(snapshot => snapshot.Status is DownloadTaskStatus.Downloading or
            DownloadTaskStatus.Connecting or DownloadTaskStatus.Inspecting or DownloadTaskStatus.Reconnecting).ToArray();
        TotalBytesPerSecond = active.Sum(snapshot => snapshot.BytesPerSecond);
        ActiveTaskCount = active.Length;
        ActiveConnectionCount = active.Sum(snapshot => snapshot.ActiveConnections);
        var knownTotal = active.Where(snapshot => snapshot.TotalBytes is > 0).Sum(snapshot => snapshot.TotalBytes!.Value);
        var knownReceived = active.Where(snapshot => snapshot.TotalBytes is > 0).Sum(snapshot => snapshot.ReceivedBytes);
        TotalProgress = knownTotal > 0 ? 100d * knownReceived / knownTotal : 0;
        TotalProgressText = active.Length == 0
            ? "没有进行中的任务"
            : $"{active.Length} 个任务 · {knownTotal switch { > 0 => $"{Math.Clamp(TotalProgress, 0, 100):0}% 总进度", _ => "总大小未知" }}";
        OnPropertyChanged(nameof(TotalSpeedText));
        OnPropertyChanged(nameof(ActiveTaskText));
        OnPropertyChanged(nameof(ActiveConnectionsText));
    }

    private static string SafeExceptionMessage(Exception exception) => exception switch
    {
        PrivateKeyPassphraseRequiredException => "需要在高级信息中解锁本机私钥。",
        PrivateKeyUnlockFailedException => "保存的私钥口令无效。",
        UnauthorizedAccessException => "本机目录或凭据访问被拒绝。",
        IOException => "网络或本机文件读写错误。",
        _ => exception.Message.Length > 180 ? exception.Message[..180] : exception.Message
    };

    partial void OnCompletionSoundEnabledChanged(bool value) => QueueSettingsSave();
    partial void OnCompletionVolumePercentChanged(int value) => QueueSettingsSave();
    partial void OnSelectedConcurrencyChanged(int value) => QueueSettingsSave();
    partial void OnAutoTuneConcurrencyChanged(bool value) => QueueSettingsSave();
}
