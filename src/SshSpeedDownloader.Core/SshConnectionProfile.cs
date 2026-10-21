using System.Globalization;
using System.Net;

namespace SshSpeedDownloader.Core;

public sealed record SshConnectionProfile(
    string Host,
    int Port,
    string Username,
    string PrivateKeyPath,
    string? TrustedHostFingerprint)
{
    public IReadOnlyList<string> TrustedHostFingerprints { get; init; } = [];
    public string? PrivateKeyIdentityId { get; init; }
    public Func<Stream>? PrivateKeyStreamProvider { get; init; }
    public bool SupportsRemoteCommandDiagnostics { get; init; } = true;
}

public static class SshConnectionProfileValidator
{
    public static bool TryValidate(SshConnectionProfile profile, out string error)
    {
        ArgumentNullException.ThrowIfNull(profile);
        error = "";

        if (string.IsNullOrWhiteSpace(profile.Host) || !IsValidHost(profile.Host))
        {
            error = "请输入有效的服务器主机名或 IP 地址。";
            return false;
        }

        if (profile.Port is < 1 or > ushort.MaxValue)
        {
            error = "SSH 端口必须在 1 到 65535 之间。";
            return false;
        }

        if (string.IsNullOrWhiteSpace(profile.Username) || profile.Username.Length > 64 ||
            profile.Username.Any(char.IsControl))
        {
            error = "请输入有效的 SSH 用户名。";
            return false;
        }

        var hasEmbeddedKey = profile.PrivateKeyStreamProvider is not null &&
            !string.IsNullOrWhiteSpace(profile.PrivateKeyIdentityId);
        if (!hasEmbeddedKey &&
            (string.IsNullOrWhiteSpace(profile.PrivateKeyPath) || !Path.IsPathFullyQualified(profile.PrivateKeyPath)))
        {
            error = "请选择一个本机私钥文件。";
            return false;
        }

        return true;
    }

    private static bool IsValidHost(string host)
    {
        var candidate = host.Trim();
        if (IPAddress.TryParse(candidate, out _))
            return true;
        if (candidate.Contains('/') || candidate.Contains('\\') || candidate.Contains('@') || candidate.Contains(':'))
            return false;

        try
        {
            var ascii = new IdnMapping().GetAscii(candidate.TrimEnd('.'));
            return Uri.CheckHostName(ascii) == UriHostNameType.Dns &&
                   ascii.Length <= 253 &&
                   ascii.Split('.').All(label => label.Length is > 0 and <= 63);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}

public static class HostKeyPin
{
    public static bool Matches(string? receivedFingerprint, SshConnectionProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return Matches(receivedFingerprint, profile.TrustedHostFingerprint) ||
            profile.TrustedHostFingerprints.Any(pin => Matches(receivedFingerprint, pin));
    }

    public static bool Matches(string? receivedFingerprint, string? trustedFingerprint)
    {
        var received = Normalize(receivedFingerprint);
        var trusted = Normalize(trustedFingerprint);
        return received.Length > 0 && trusted.Length > 0 &&
               string.Equals(received, trusted, StringComparison.Ordinal);
    }

    public static string Normalize(string? fingerprint)
    {
        var normalized = (fingerprint ?? "").Trim();
        if (normalized.StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase))
            normalized = normalized["SHA256:".Length..];
        return normalized.TrimEnd('=');
    }
}
