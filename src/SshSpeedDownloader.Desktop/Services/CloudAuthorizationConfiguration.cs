using SshSpeedDownloader.Core;
using SshSpeedDownloader.Transport.IdentityProviders;

namespace SshSpeedDownloader.Desktop.Services;

public static class CloudAuthorizationConfiguration
{
    private static readonly string[] AliyunHostKeyPins =
    [
        "SHA256:mlPaG+lfjBo92T/OG7fVrVz4sxY+rM+1hTxT+hY9X4k",
        "SHA256:FjMNC1WcRbxcpiNwiVzEauHETLOWagnixLgQtWoSNyk",
        "SHA256:rkxyIaeyapIwt1zGy+JPffafL8ClWOYRQIvkvuFiGls"
    ];

    public static IReadOnlyList<string> TrustedRelayHostKeyPins => AliyunHostKeyPins;

    public static CloudDeviceAuthorizationOptions CreateDefault() => new(
        new Uri("https://auth.modiconnect.cn/"),
        new ServerConnectionConfiguration(
            "39.105.70.140",
            22,
            "modi-relay",
            AliyunHostKeyPins));
}
