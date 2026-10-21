using System.Runtime.Versioning;
using Renci.SshNet;
using SshSpeedDownloader.Transport.IdentityProviders;

namespace SshSpeedDownloader.Tests;

[SupportedOSPlatform("windows")]
public sealed class WindowsDeviceIdentityStoreTests
{
    [Fact]
    public async Task DeviceIdentityPersistsAndPrivateKeyRemainsProtectedAtRest()
    {
        using var directory = new TemporaryDirectory();
        var statePath = Path.Combine(directory.Path, "identity.json");
        var firstStore = new WindowsDeviceIdentityStore(statePath, "Test Windows device");

        var first = await firstStore.LoadOrCreateAsync();
        var storedJson = await File.ReadAllTextAsync(statePath);
        using var privateKeyStream = firstStore.OpenPrivateKeyStream();
        using var privateKey = new PrivateKeyFile(privateKeyStream);
        var signature = firstStore.Sign("signed identity check"u8);

        Assert.Matches("^mdp-[a-z2-7]{26}$", first.DeviceId);
        Assert.StartsWith("SHA256:", first.PublicKeyFingerprint);
        Assert.DoesNotContain("PRIVATE KEY", storedJson, StringComparison.Ordinal);
        Assert.NotEmpty(signature);

        var secondStore = new WindowsDeviceIdentityStore(statePath, "Ignored after first creation");
        var second = await secondStore.LoadOrCreateAsync();

        Assert.Equal(first, second);
    }

    [Fact]
    public async Task RequestIdempotencyAndApprovalStateSurviveRestart()
    {
        using var directory = new TemporaryDirectory();
        var statePath = Path.Combine(directory.Path, "identity.json");
        var firstStore = new WindowsDeviceIdentityStore(statePath, "Test Windows device");
        await firstStore.LoadOrCreateAsync();
        var state = new DeviceRequestState(new string('a', 32), new string('b', 32));

        await firstStore.SaveRequestStateAsync(state);

        var reopened = new WindowsDeviceIdentityStore(statePath, "Test Windows device");
        await reopened.LoadOrCreateAsync();
        Assert.Equal(state, await reopened.LoadRequestStateAsync());
    }

    [Fact]
    public async Task CorruptIdentityFailsClosedInsteadOfGeneratingANewDevice()
    {
        using var directory = new TemporaryDirectory();
        var statePath = Path.Combine(directory.Path, "identity.json");
        await File.WriteAllTextAsync(statePath, "{\"schemaVersion\":999}");
        var store = new WindowsDeviceIdentityStore(statePath, "Test Windows device");

        await Assert.ThrowsAsync<InvalidDataException>(() => store.LoadOrCreateAsync());

        Assert.Equal("{\"schemaVersion\":999}", await File.ReadAllTextAsync(statePath));
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            "modi-device-identity-" + Guid.NewGuid().ToString("N"));

        public TemporaryDirectory() => Directory.CreateDirectory(Path);

        public void Dispose()
        {
            if (Directory.Exists(Path))
                Directory.Delete(Path, recursive: true);
        }
    }
}
