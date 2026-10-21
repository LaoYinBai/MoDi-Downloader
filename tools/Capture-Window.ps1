param([Parameter(Mandatory)][int]$ProcessId, [Parameter(Mandatory)][string]$OutputPath, [int]$Width, [int]$Height)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class DownloaderWindowCapture {
 [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left,Top,Right,Bottom; }
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
 [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
 [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr order, int x, int y, int w, int z, uint flags);
}
'@
$process = Get-Process -Id $ProcessId
if ($process.ProcessName -ne 'MoDiDownloader') { throw 'Refusing to capture an unrelated process.' }
$window = $process.MainWindowHandle
if ($window -eq [IntPtr]::Zero) { throw 'Application has no visible window.' }
if ($Width -gt 0 -and $Height -gt 0) {
    [DownloaderWindowCapture]::SetWindowPos($window, [IntPtr]::Zero, 80, 60, $Width, $Height, 20) | Out-Null
}
Start-Sleep -Milliseconds 650
$rect = [DownloaderWindowCapture+RECT]::new()
if (-not [DownloaderWindowCapture]::GetWindowRect($window,[ref]$rect)) { throw 'Window capture failed.' }
$bitmap = [Drawing.Bitmap]::new($rect.Right-$rect.Left, $rect.Bottom-$rect.Top)
$graphics = [Drawing.Graphics]::FromImage($bitmap)
try {
    $dc = $graphics.GetHdc()
    try { $captured = [DownloaderWindowCapture]::PrintWindow($window, $dc, 2) }
    finally { $graphics.ReleaseHdc($dc) }
    if (-not $captured) { throw 'Target-window capture failed; desktop capture is not permitted.' }
    $bitmap.Save([IO.Path]::GetFullPath($OutputPath),[Drawing.Imaging.ImageFormat]::Png)
} finally { $graphics.Dispose(); $bitmap.Dispose() }
