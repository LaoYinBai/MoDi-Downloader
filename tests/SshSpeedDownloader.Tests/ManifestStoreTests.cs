using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Tests;

public sealed class ManifestStoreTests
{
    [Fact]
    public async Task SavesResumeStateAtomicallyWithoutCredentialFields()
    {
        var root = Path.Combine(Path.GetTempPath(), $"modi-downloader-test-{Guid.NewGuid():N}");
        var id = Guid.NewGuid();
        var targetPath = Path.Combine(root, "payload.bin");
        var manifest = new DownloadManifest
        {
            Id = id,
            SourceUrl = "https://example.com/payload.bin?token=secret",
            FinalUrl = "https://cdn.example.com/payload.bin?token=secret",
            TargetPath = targetPath,
            PartialPath = targetPath + ".modi.part",
            Resource = new ResourceIdentity(1_024, true, "\"stable\"", null),
            ChunkSizeBytes = 256,
            RequestedConcurrency = 8,
            AutoTuneConcurrency = true,
            CompletedChunkIndexes = [0, 2]
        };

        try
        {
            var store = new JsonDownloadManifestStore(root);
            await store.SaveAsync(manifest, CancellationToken.None);

            var loaded = await store.LoadAllAsync(CancellationToken.None);
            var restored = Assert.Single(loaded);
            Assert.Equal(id, restored.Id);
            Assert.Equal(targetPath + ".modi.part", restored.PartialPath);
            Assert.Equal(new[] { 0, 2 }, restored.CompletedChunkIndexes);

            var json = await File.ReadAllTextAsync(Path.Combine(root, id + ".json"));
            Assert.DoesNotContain("passphrase", json, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("privateKeyContents", json, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task RejectsManifestChunkIndexesOutsideTheResource()
    {
        var root = Path.Combine(Path.GetTempPath(), $"modi-downloader-test-{Guid.NewGuid():N}");
        var targetPath = Path.Combine(root, "payload.bin");
        var manifest = new DownloadManifest
        {
            Id = Guid.NewGuid(),
            SourceUrl = "https://example.com/payload.bin",
            TargetPath = targetPath,
            PartialPath = targetPath + ".modi.part",
            Resource = new ResourceIdentity(10, true, "\"stable\"", null),
            ChunkSizeBytes = 4,
            CompletedChunkIndexes = [3]
        };

        var store = new JsonDownloadManifestStore(root);
        await Assert.ThrowsAsync<InvalidDataException>(() => store.SaveAsync(manifest, CancellationToken.None));
    }
}
