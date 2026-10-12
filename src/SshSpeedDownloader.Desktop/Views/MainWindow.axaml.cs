using Avalonia.Controls;
using Avalonia.Platform.Storage;
using SshSpeedDownloader.Desktop.ViewModels;

namespace SshSpeedDownloader.Desktop.Views;

public partial class MainWindow : Window
{
    private MainViewModel? _viewModel;
    private bool _shutdownStarted;
    private bool _shutdownFinished;

    public MainWindow()
    {
        InitializeComponent();
        Opened += MainWindow_Opened;
        Closing += MainWindow_Closing;
    }

    private async void MainWindow_Opened(object? sender, EventArgs e)
    {
        if (DataContext is not MainViewModel viewModel)
            return;
        _viewModel = viewModel;
        _viewModel.ActivateWindowRequested += ViewModel_ActivateWindowRequested;
        await _viewModel.InitializeAsync();
    }

    private async void MainWindow_Closing(object? sender, WindowClosingEventArgs e)
    {
        if (_shutdownFinished)
            return;
        e.Cancel = true;
        if (_shutdownStarted)
            return;

        _shutdownStarted = true;
        if (_viewModel is not null)
        {
            _viewModel.ActivateWindowRequested -= ViewModel_ActivateWindowRequested;
            await _viewModel.ShutdownAsync();
        }
        _shutdownFinished = true;
        Close();
    }

    private async void BrowseTaskFolder_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        var folder = await PickFolderAsync("选择本任务的本地保存目录");
        if (folder is not null)
            _viewModel?.SetTaskDownloadDirectory(folder);
    }

    private async void BrowseDefaultFolder_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        var folder = await PickFolderAsync("选择默认下载目录");
        if (folder is not null && _viewModel is not null)
            await _viewModel.ApplyDefaultDirectoryAsync(folder);
    }

    private async Task<string?> PickFolderAsync(string title)
    {
        var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = title,
            AllowMultiple = false
        });
        return folders.Count > 0 ? folders[0].TryGetLocalPath() : null;
    }

    private void ViewModel_ActivateWindowRequested(object? sender, EventArgs e)
    {
        WindowState = WindowState.Normal;
        Activate();
    }
}
