using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Renci.SshNet;
using SshSpeedDownloader.Core;
using SshSpeedDownloader.Transport.IdentityProviders;
using Xunit;

namespace SshSpeedDownloader.Tests;

[SupportedOSPlatform("windows")]
public sealed class DeviceIdentityStoreTests
{
    [Fact]
    public void DeviceIdFactoryProducesLowercaseUnpaddedBase32ForExactly128Bits()
    {
        Assert.Equal("mdp-aaaaaaaaaaaaaaaaaaaaaaaaaa", DeviceIdFactory.Create(new byte[16]));
        Assert.Equal("mdp-77777777777777777777777774", DeviceIdFactory.Create(Enumerable.Repeat((byte)0xff, 16).ToArray()));
        Assert.Throws<ArgumentException>(() => DeviceIdFactory.Create(new byte[15]));
        Assert.Throws<ArgumentException>(() => DeviceIdFactory.Create(new byte[17]));
    }

    [Fact]
    public async Task DeviceIdentityAndP256KeyPersistAcrossStoreInstances()
    {
        using var directory = new TemporaryDirectory();
        var firstStore = new WindowsDeviceIdentityStore(directory.IdentityDirectory, "Test workstation");
        var first = await firstStore.LoadOrCreateAsync(CancellationToken.None);
        var persistedFiles = Directory.GetFiles(directory.IdentityDirectory);

        var secondStore = new WindowsDeviceIdentityStore(directory.IdentityDirectory, "Ignored rename");
        var second = await secondStore.LoadOrCreateAsync(CancellationToken.None);

        Assert.Equal(first.DeviceIdentity, second.DeviceIdentity);
        Assert.Equal(first.DeviceKeyId, first.DeviceIdentity.DeviceId);
        Assert.Equal(first.DeviceKeyId, second.DeviceKeyId);
        Assert.Equal("Test workstation", second.DeviceIdentity.DisplayName);
        Assert.Single(persistedFiles);
        Assert.True(DeviceIdFactory.IsValid(first.DeviceKeyId));
        AssertP256PrivateKeyMatchesPublicKey(first);
        AssertP256PrivateKeyMatchesPublicKey(second);
    }

    [Fact]
    public async Task SeparateInstallationsGenerateDifferentDeviceIdsAndKeyFingerprints()
    {
        using var firstDirectory = new TemporaryDirectory();
        using var secondDirectory = new TemporaryDirectory();
        var first = await new WindowsDeviceIdentityStore(firstDirectory.IdentityDirectory, "First")
            .LoadOrCreateAsync(CancellationToken.None);
        var second = await new WindowsDeviceIdentityStore(secondDirectory.IdentityDirectory, "Second")
            .LoadOrCreateAsync(CancellationToken.None);

        Assert.NotEqual(first.DeviceIdentity.DeviceId, second.DeviceIdentity.DeviceId);
        Assert.NotEqual(first.DeviceIdentity.PublicKeyFingerprint, second.DeviceIdentity.PublicKeyFingerprint);
    }

    [Fact]
    public async Task ProtectedIdentityFileContainsNoPlaintextPemOrKeyBytes()
    {
        using var directory = new TemporaryDirectory();
        var identity = await new WindowsDeviceIdentityStore(directory.IdentityDirectory, "Test device")
            .LoadOrCreateAsync(CancellationToken.None);
        byte[] privatePem;
        using (var stream = identity.OpenPrivateKeyStream())
        using (var buffer = new MemoryStream())
        {
            await stream.CopyToAsync(buffer);
            privatePem = buffer.ToArray();
        }

        var file = Assert.Single(Directory.GetFiles(directory.IdentityDirectory));
        var storedBytes = await File.ReadAllBytesAsync(file);
        var storedJson = Encoding.UTF8.GetString(storedBytes);
        Assert.DoesNotContain("-----BEGIN PRIVATE KEY-----", storedJson, StringComparison.Ordinal);
        Assert.False(ContainsSequence(storedBytes, privatePem));
        CryptographicOperations.ZeroMemory(privatePem);
        CryptographicOperations.ZeroMemory(storedBytes);
    }

    [Fact]
    public async Task EmbeddedPrivateKeyStreamIsAcceptedBySshNetWithoutAPlaintextPath()
    {
        using var directory = new TemporaryDirectory();
        var identity = await new WindowsDeviceIdentityStore(directory.IdentityDirectory, "Test device")
            .LoadOrCreateAsync(CancellationToken.None);
        var profile = new SshConnectionProfile("example.test", 22, "modi-download", "", null)
        {
            PrivateKeyIdentityId = identity.DeviceKeyId,
            PrivateKeyStreamProvider = identity.OpenPrivateKeyStream,
            TrustedHostFingerprints = ["SHA256:test-pin"]
        };

        Assert.True(SshConnectionProfileValidator.TryValidate(profile, out _));
        using var stream = profile.PrivateKeyStreamProvider!();
        using var privateKey = new PrivateKeyFile(stream);
        Assert.NotNull(privateKey);
        Assert.Empty(Directory.GetFiles(directory.IdentityDirectory, "*.pem"));
    }

    [Fact]
    public async Task CorruptOrUnprotectableIdentityFailsWithoutRegeneratingIt()
    {
        using var directory = new TemporaryDirectory();
        var store = new WindowsDeviceIdentityStore(directory.IdentityDirectory, "Test device");
        _ = await store.LoadOrCreateAsync(CancellationToken.None);
        var file = Assert.Single(Directory.GetFiles(directory.IdentityDirectory));
        var invalidBlob = await File.ReadAllBytesAsync(file);
        var document = JsonDocument.Parse(invalidBlob);
        var protectedBlob = Convert.FromBase64String(document.RootElement.GetProperty("protectedPrivateKeyBase64").GetString()!);
        CryptographicOperations.ZeroMemory(invalidBlob);
        document.Dispose();
        protectedBlob[0] ^= 0xff;
        var tampered = JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = 1,
            deviceId = "mdp-aaaaaaaaaaaaaaaaaaaaaaaaaa",
            displayName = "Test device",
            openSshPublicKey = "ssh-ed25519 AQID",
            publicKeyFingerprint = "SHA256:A5BYxvLAy0ksUzsKTRTvd8wPeKvMztUofYShogEc+4E",
            protectedPrivateKeyBase64 = Convert.ToBase64String(protectedBlob)
        });
        await File.WriteAllBytesAsync(file, tampered);

        var before = await File.ReadAllBytesAsync(file);
        await Assert.ThrowsAsync<DeviceIdentityStoreException>(() => store.LoadOrCreateAsync(CancellationToken.None));
        var after = await File.ReadAllBytesAsync(file);
        Assert.Equal(before, after);
        CryptographicOperations.ZeroMemory(protectedBlob);
        CryptographicOperations.ZeroMemory(tampered);
        CryptographicOperations.ZeroMemory(before);
        CryptographicOperations.ZeroMemory(after);
    }

    [Fact]
    public async Task ForgetRemovesOnlyThisInstallationIdentity()
    {
        using var directory = new TemporaryDirectory();
        var unrelatedSettings = Path.Combine(directory.Root, "settings.json");
        var unrelatedDownload = Path.Combine(directory.Root, "finished.bin");
        await File.WriteAllTextAsync(unrelatedSettings, "{}");
        await File.WriteAllBytesAsync(unrelatedDownload, [1, 2, 3]);
        var store = new WindowsDeviceIdentityStore(directory.IdentityDirectory, "Test device");
        var oldIdentity = await store.LoadOrCreateAsync(CancellationToken.None);

        Assert.True(await store.ForgetLocalIdentityAsync(CancellationToken.None));
        Assert.Empty(Directory.GetFiles(directory.IdentityDirectory));
        Assert.True(File.Exists(unrelatedSettings));
        Assert.True(File.Exists(unrelatedDownload));
        var newIdentity = await store.LoadOrCreateAsync(CancellationToken.None);
        Assert.NotEqual(oldIdentity.DeviceKeyId, newIdentity.DeviceKeyId);
    }

    private static void AssertP256PrivateKeyMatchesPublicKey(LocalDeviceIdentity identity)
    {
        byte[] pem;
        using (var stream = identity.OpenPrivateKeyStream())
        using (var output = new MemoryStream())
        {
            stream.CopyTo(output);
            pem = output.ToArray();
        }

        var chars = Encoding.UTF8.GetChars(pem);
        try
        {
            using var privateKey = ECDsa.Create();
            privateKey.ImportFromPem(chars);
            Assert.Equal(256, privateKey.KeySize);
            var publicPoint = ReadOpenSshP256Point(identity.DeviceIdentity.PublicKey);
            var parameters = privateKey.ExportParameters(false);
            Assert.Equal(publicPoint.X, parameters.Q.X);
            Assert.Equal(publicPoint.Y, parameters.Q.Y);
        }
        finally
        {
            Array.Clear(chars);
            CryptographicOperations.ZeroMemory(pem);
        }
    }

    private static ECPoint ReadOpenSshP256Point(string publicKey)
    {
        var fields = publicKey.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal("ecdsa-sha2-nistp256", fields[0]);
        var blob = Convert.FromBase64String(fields[1]);
        var offset = 0;
        Assert.Equal("ecdsa-sha2-nistp256", ReadSshString(blob, ref offset));
        Assert.Equal("nistp256", ReadSshString(blob, ref offset));
        var point = ReadSshBytes(blob, ref offset);
        Assert.Equal(blob.Length, offset);
        Assert.Equal(65, point.Length);
        Assert.Equal((byte)0x04, point[0]);
        return new ECPoint { X = point[1..33], Y = point[33..65] };
    }

    private static string ReadSshString(byte[] blob, ref int offset) => Encoding.ASCII.GetString(ReadSshBytes(blob, ref offset));

    private static byte[] ReadSshBytes(byte[] blob, ref int offset)
    {
        var length = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(offset, 4));
        offset += 4;
        var value = blob.AsSpan(offset, checked((int)length)).ToArray();
        offset += checked((int)length);
        return value;
    }

    private static bool ContainsSequence(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || needle.Length > haystack.Length) return false;
        for (var index = 0; index <= haystack.Length - needle.Length; index++)
        {
            if (haystack.AsSpan(index, needle.Length).SequenceEqual(needle)) return true;
        }
        return false;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Root = Path.Combine(Path.GetTempPath(), $"modi-device-identity-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Root);
            IdentityDirectory = Path.Combine(Root, "identity");
        }

        public string Root { get; }
        public string IdentityDirectory { get; }

        public void Dispose()
        {
            if (Directory.Exists(IdentityDirectory))
            {
                foreach (var file in Directory.GetFiles(IdentityDirectory)) File.Delete(file);
                Directory.Delete(IdentityDirectory);
            }
            foreach (var file in Directory.GetFiles(Root)) File.Delete(file);
            if (Directory.Exists(Root)) Directory.Delete(Root);
        }
    }
}
