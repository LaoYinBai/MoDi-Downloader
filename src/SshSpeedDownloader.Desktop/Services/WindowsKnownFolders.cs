using System.Runtime.InteropServices;

namespace SshSpeedDownloader.Desktop.Services;

public static class WindowsKnownFolders
{
    private static readonly Guid DownloadsFolderId = new("374DE290-123F-4565-9164-39C4925E467B");

    public static string GetDownloadsPath()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("The Windows Downloads Known Folder is only available on Windows.");

        var folderId = DownloadsFolderId;
        var result = SHGetKnownFolderPath(ref folderId, 0, IntPtr.Zero, out var pathPointer);
        Marshal.ThrowExceptionForHR(result);
        try
        {
            var path = Marshal.PtrToStringUni(pathPointer);
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
                throw new IOException("Windows did not return a valid Downloads folder path.");
            return path;
        }
        finally
        {
            if (pathPointer != IntPtr.Zero)
                Marshal.FreeCoTaskMem(pathPointer);
        }
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHGetKnownFolderPath(
        ref Guid folderId,
        uint flags,
        IntPtr token,
        out IntPtr path);
}

public static class WritableDirectoryProbe
{
    public static bool TryCheck(string path, out string error)
    {
        error = "";
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || !Directory.Exists(path))
        {
            error = "所选目录不存在；请先在 Windows 中创建该目录，或重新选择。";
            return false;
        }

        var probePath = Path.Combine(path, $".modi-write-check-{Guid.NewGuid():N}.tmp");
        try
        {
            using var probe = new FileStream(
                probePath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                1,
                FileOptions.DeleteOnClose);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            error = "所选目录不可写；请检查 Windows 权限或选择其他目录。";
            return false;
        }
    }
}
