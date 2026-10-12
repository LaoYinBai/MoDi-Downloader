namespace SshSpeedDownloader.Core;

public static class UrlSafety
{
    public static bool TryValidateDownloadUri(string? value, out Uri? uri)
    {
        uri = null;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var candidate) ||
            candidate.Scheme is not ("http" or "https") ||
            string.IsNullOrWhiteSpace(candidate.Host) ||
            !string.IsNullOrEmpty(candidate.UserInfo))
            return false;

        uri = candidate;
        return true;
    }

    public static string RedactForLog(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        var builder = new UriBuilder(uri) { Query = string.IsNullOrEmpty(uri.Query) ? "" : "redacted", Fragment = "" };
        return builder.Uri.AbsoluteUri;
    }
}
