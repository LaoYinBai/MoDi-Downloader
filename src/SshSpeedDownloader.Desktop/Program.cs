using Avalonia;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace SshSpeedDownloader.Desktop;

sealed class Program
{
    // Initialization code. Don't use any Avalonia, third-party APIs or any
    // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
    // yet and stuff might break.
    [STAThread]
    public static void Main(string[] args)
    {
        using var identity = WindowsIdentity.GetCurrent();
        using var instance = new Mutex(true, $@"Local\MoDiDownloader.{identity.User?.Value}", out var firstInstance);
        if (!firstInstance)
        {
            foreach (var process in Process.GetProcessesByName("MoDiDownloader"))
            {
                using (process)
                {
                    if (process.Id == Environment.ProcessId || process.MainWindowHandle == IntPtr.Zero)
                        continue;
                    ShowWindow(process.MainWindowHandle, 9);
                    SetForegroundWindow(process.MainWindowHandle);
                    break;
                }
            }
            return;
        }
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr window);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr window, int command);

    // Avalonia configuration, don't remove; also used by visual designer.
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
#if DEBUG
            .WithDeveloperTools(_ => { })
#endif
            .WithInterFont()
            .LogToTrace();
}
