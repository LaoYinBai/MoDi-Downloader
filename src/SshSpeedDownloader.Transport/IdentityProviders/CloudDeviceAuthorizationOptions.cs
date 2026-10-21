using System.Text.RegularExpressions;
using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Transport.IdentityProviders;

public sealed record CloudDeviceAuthorizationOptions(
    Uri ApiBaseUri,
    ServerConnectionConfiguration Relay)
{
    private static readonly Regex HostFingerprintPattern =
        new("^SHA256:[A-Za-z0-9+/]{43}$", RegexOptions.CultureInvariant);

    public void Validate()
    {
        if (ApiBaseUri is null ||
            ApiBaseUri.Scheme != Uri.UriSchemeHttps ||
            !ApiBaseUri.Host.Equals("auth.modiconnect.cn", StringComparison.OrdinalIgnoreCase) ||
            ApiBaseUri.Port != 443 ||
            ApiBaseUri.UserInfo.Length != 0 ||
            ApiBaseUri.Query.Length != 0 ||
            ApiBaseUri.Fragment.Length != 0 ||
            ApiBaseUri.AbsolutePath != "/")
            throw new ArgumentException("Authorization API must use the configured HTTPS origin.", nameof(ApiBaseUri));

        ArgumentNullException.ThrowIfNull(Relay);
        if (!Relay.Username.Equals("modi-relay", StringComparison.Ordinal) ||
            Relay.TrustedHostFingerprints.Count == 0 ||
            Relay.TrustedHostFingerprints.Any(pin => !HostFingerprintPattern.IsMatch(pin)))
            throw new ArgumentException("Restricted relay identity or host-key pins are invalid.", nameof(Relay));

        var profile = new SshConnectionProfile(Relay.Host, Relay.Port, Relay.Username, "", null)
        {
            PrivateKeyIdentityId = "profile-validation",
            PrivateKeyStreamProvider = static () => Stream.Null,
            TrustedHostFingerprints = Relay.TrustedHostFingerprints
        };
        if (!SshConnectionProfileValidator.TryValidate(profile, out var error))
            throw new ArgumentException(error, nameof(Relay));
    }
}
