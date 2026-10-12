using System.Text;

namespace SshSpeedDownloader.Core;

public static class DownloadFileName
{
    private static readonly HashSet<string> ReservedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    public static string Sanitize(string? value)
    {
        var leaf = (value ?? "").Replace('\\', '/').Split('/').LastOrDefault() ?? "";
        var invalid = Path.GetInvalidFileNameChars().ToHashSet();
        foreach (var character in "<>:\"/\\|?*")
            invalid.Add(character);

        var builder = new StringBuilder(leaf.Length);
        foreach (var character in leaf)
            builder.Append(char.IsControl(character) || invalid.Contains(character) ? '_' : character);

        var result = builder.ToString().Trim().TrimEnd('.', ' ');
        if (result is "" or "." or "..")
            result = "download.bin";

        var basename = result.Split('.')[0];
        if (ReservedNames.Contains(basename))
            result = $"_{result}";

        return result.Length <= 180 ? result : result[..180].TrimEnd('.', ' ');
    }
}
