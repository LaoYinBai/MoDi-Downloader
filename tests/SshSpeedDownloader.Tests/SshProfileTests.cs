using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Tests;

public sealed class SshProfileTests
{
    [Fact]
    public void HostFingerprintPinsIgnoreOnlyTheOpenSshDisplayPrefixAndPadding()
    {
        Assert.True(HostKeyPin.Matches("SHA256:AbC123=", "AbC123"));
        Assert.True(HostKeyPin.Matches("AbC123", "SHA256:AbC123=="));
        Assert.False(HostKeyPin.Matches("SHA256:AbC123", "SHA256:abc123"));
        Assert.False(HostKeyPin.Matches("", "SHA256:AbC123"));
    }

    [Theory]
    [InlineData("example.com", 22, "admin", true)]
    [InlineData("", 22, "admin", false)]
    [InlineData("example.com", 0, "admin", false)]
    [InlineData("example.com", 22, "", false)]
    [InlineData("example.com/../../x", 22, "admin", false)]
    public void ValidatesTheHostPortAndUsernameBeforeConnecting(string host, int port, string user, bool expected)
    {
        var profile = new SshConnectionProfile(host, port, user, "C:\\keys\\id_ed25519", null);

        Assert.Equal(expected, SshConnectionProfileValidator.TryValidate(profile, out _));
    }

    [Fact]
    public void MatchesAnyPinnedKnownHostKeyFingerprint()
    {
        var profile = new SshConnectionProfile("example.com", 22, "admin", "C:\\keys\\id", null)
        {
            TrustedHostFingerprints = ["SHA256:first", "SHA256:second"]
        };

        Assert.True(HostKeyPin.Matches("second", profile));
        Assert.False(HostKeyPin.Matches("third", profile));
    }

    [Fact]
    public void AllowsAConfiguredEmbeddedPrivateKeyWithoutAFilePath()
    {
        var profile = new SshConnectionProfile("example.com", 22, "admin", "", null)
        {
            PrivateKeyIdentityId = "embedded-test-key",
            PrivateKeyStreamProvider = () => new MemoryStream([1, 2, 3]),
            TrustedHostFingerprints = ["SHA256:pin"]
        };

        Assert.True(SshConnectionProfileValidator.TryValidate(profile, out _));
    }
}
