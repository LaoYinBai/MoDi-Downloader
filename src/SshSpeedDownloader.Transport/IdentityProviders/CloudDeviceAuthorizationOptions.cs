using System.Globalization;
using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Transport.IdentityProviders;

public sealed record CloudDeviceAuthorizationOptions(
    string ApiBaseUrl,
    string RelayHost,
    int RelayPort,
    string RelayUsername,
    IReadOnlyList<string> TrustedHostFingerprints)
{
    public bool IsApiConfigured => TryGetApiBaseUri(out _);

    public bool IsRelayConfigured => TryGetServerConfiguration(out _);

    public static CloudDeviceAuthorizationOptions FromEnvironment() => new(
        Environment.GetEnvironmentVariable("MODI_AUTH_API_BASE_URL") ?? "",
        Environment.GetEnvironmentVariable("MODI_AUTH_RELAY_HOST") ?? "",
        int.TryParse(Environment.GetEnvironmentVariable("MODI_AUTH_RELAY_PORT"), NumberStyles.None,
            CultureInfo.InvariantCulture, out var port) ? port : 0,
        Environment.GetEnvironmentVariable("MODI_AUTH_RELAY_USERNAME") ?? "",
        (Environment.GetEnvironmentVariable("MODI_AUTH_RELAY_HOST_FINGERPRINTS") ?? "")
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    public bool TryGetApiBaseUri(out Uri? baseUri)
    {
        baseUri = null;
        if (!Uri.TryCreate(ApiBaseUrl, UriKind.Absolute, out var parsed) ||
            !StringComparer.OrdinalIgnoreCase.Equals(parsed.Scheme, Uri.UriSchemeHttps) ||
            string.IsNullOrEmpty(parsed.Host) || !string.IsNullOrEmpty(parsed.UserInfo) ||
            !string.IsNullOrEmpty(parsed.Query) || !string.IsNullOrEmpty(parsed.Fragment) ||
            !StringComparer.Ordinal.Equals(parsed.AbsolutePath, "/"))
        {
            return false;
        }

        baseUri = new Uri(parsed.GetLeftPart(UriPartial.Authority) + "/", UriKind.Absolute);
        return true;
    }

    public bool TryGetServerConfiguration(out ServerConnectionConfiguration? configuration)
    {
        configuration = null;
        if (string.IsNullOrWhiteSpace(RelayHost) || RelayHost.Any(char.IsWhiteSpace) ||
            Uri.CheckHostName(RelayHost) == UriHostNameType.Unknown || RelayHost.Contains('/') ||
            RelayHost.Contains('@') || RelayPort is <= 0 or > 65535 ||
            string.IsNullOrWhiteSpace(RelayUsername) ||
            RelayUsername.Equals("admin", StringComparison.OrdinalIgnoreCase) ||
            RelayUsername.Equals("root", StringComparison.OrdinalIgnoreCase) ||
            RelayUsername.Length > 64 ||
            RelayUsername.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '_' and not '-'))
        {
            return false;
        }

        var pins = TrustedHostFingerprints?.ToArray() ?? [];
        if (pins.Length == 0 || pins.Any(pin => !IsValidSha256Fingerprint(pin)))
            return false;

        configuration = new ServerConnectionConfiguration(RelayHost, RelayPort, RelayUsername, pins);
        return true;
    }

    private static bool IsValidSha256Fingerprint(string? fingerprint)
    {
        const string prefix = "SHA256:";
        if (fingerprint is null || !fingerprint.StartsWith(prefix, StringComparison.Ordinal)) return false;
        var body = fingerprint[prefix.Length..];
        if (body.Length != 43) return false;
        try
        {
            var decoded = Convert.FromBase64String(body + "=");
            return decoded.Length == 32 &&
                StringComparer.Ordinal.Equals(Convert.ToBase64String(decoded).TrimEnd('='), body);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
