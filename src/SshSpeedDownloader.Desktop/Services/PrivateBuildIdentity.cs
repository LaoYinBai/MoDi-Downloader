using System.Reflection;
using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Desktop.Services;

public static class PrivateBuildIdentity
{
    private const string EmbeddedResourceName = "SshSpeedDownloader.Desktop.PrivateIdentity.key";
    public const string IdentityId = "private-aliyun-r15x-downloader-v1";
    public const string Host = "39.105.70.140";
    public const int Port = 22;
    public const string Username = "admin";

    private static readonly string[] KnownHostPins =
    [
        "SHA256:mlPaG+lfjBo92T/OG7fVrVz4sxY+rM+1hTxT+hY9X4k",
        "SHA256:FjMNC1WcRbxcpiNwiVzEauHETLOWagnixLgQtWoSNyk",
        "SHA256:rkxyIaeyapIwt1zGy+JPffafL8ClWOYRQIvkvuFiGls"
    ];

    public static bool HasEmbeddedIdentity =>
        Assembly.GetExecutingAssembly().GetManifestResourceInfo(EmbeddedResourceName) is not null;

    public static SshConnectionProfile? CreateProfile()
    {
        if (!HasEmbeddedIdentity)
            return null;

        return new SshConnectionProfile(Host, Port, Username, "", null)
        {
            PrivateKeyIdentityId = IdentityId,
            PrivateKeyStreamProvider = OpenPrivateKey,
            TrustedHostFingerprints = KnownHostPins
        };
    }

    private static Stream OpenPrivateKey() =>
        Assembly.GetExecutingAssembly().GetManifestResourceStream(EmbeddedResourceName)
        ?? throw new InvalidOperationException("Private build identity resource is missing.");
}
