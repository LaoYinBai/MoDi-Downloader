using System.Text.Json;

namespace SshSpeedDownloader.Core;

public sealed class JsonDownloadManifestStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    private readonly string _rootDirectory;

    public JsonDownloadManifestStore() : this(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "MoDiDownloader",
        "Tasks"))
    {
    }

    public JsonDownloadManifestStore(string rootDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootDirectory);
        _rootDirectory = Path.GetFullPath(rootDirectory);
    }

    public async Task SaveAsync(DownloadManifest manifest, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        Validate(manifest);
        Directory.CreateDirectory(_rootDirectory);

        var finalPath = GetManifestPath(manifest.Id);
        var temporaryPath = Path.Combine(_rootDirectory, $".{manifest.Id:N}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(
                temporaryPath,
                new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                    BufferSize = 16 * 1024,
                    Options = FileOptions.Asynchronous | FileOptions.WriteThrough
                }))
            {
                await JsonSerializer.SerializeAsync(stream, manifest, JsonOptions, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, finalPath, overwrite: true);
        }
        finally
        {
            try
            {
                File.Delete(temporaryPath);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    public async Task<IReadOnlyList<DownloadManifest>> LoadAllAsync(CancellationToken cancellationToken)
    {
        if (!Directory.Exists(_rootDirectory))
            return Array.Empty<DownloadManifest>();

        var manifests = new List<DownloadManifest>();
        foreach (var file in Directory.EnumerateFiles(_rootDirectory, "*.json", SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                await using var stream = new FileStream(
                    file,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    16 * 1024,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                var manifest = await JsonSerializer.DeserializeAsync<DownloadManifest>(
                    stream,
                    JsonOptions,
                    cancellationToken).ConfigureAwait(false);
                if (manifest is null || !string.Equals(Path.GetFileName(file), $"{manifest.Id}.json", StringComparison.OrdinalIgnoreCase))
                    continue;

                try
                {
                    Validate(manifest);
                    manifests.Add(manifest);
                }
                catch (InvalidDataException)
                {
                }
            }
            catch (JsonException)
            {
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return manifests;
    }

    public Task DeleteAsync(Guid id, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var path = GetManifestPath(id);
        if (File.Exists(path))
            File.Delete(path);
        return Task.CompletedTask;
    }

    private string GetManifestPath(Guid id) => Path.Combine(_rootDirectory, $"{id}.json");

    private static void Validate(DownloadManifest manifest)
    {
        if (manifest.Id == Guid.Empty)
            throw new InvalidDataException("Manifest id is invalid.");
        if (manifest.Resource is null || manifest.CompletedChunkIndexes is null)
            throw new InvalidDataException("Manifest resource state is missing.");
        if (!UrlSafety.TryValidateDownloadUri(manifest.SourceUrl, out _))
            throw new InvalidDataException("Manifest source URL is invalid.");
        if (string.IsNullOrWhiteSpace(manifest.TargetPath) || !Path.IsPathFullyQualified(manifest.TargetPath))
            throw new InvalidDataException("Manifest target path is invalid.");

        var target = Path.GetFullPath(manifest.TargetPath);
        var partial = Path.GetFullPath(manifest.PartialPath);
        if (!string.Equals(partial, target + ".modi.part", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Manifest partial path does not match the target path.");
        if (manifest.ChunkSizeBytes <= 0 || manifest.RequestedConcurrency is < 1 or > 64 ||
            manifest.RetryCount < 0 || manifest.StreamBytesWritten < 0 || manifest.Resource.TotalLength < 0)
            throw new InvalidDataException("Manifest download state is invalid.");
        if (manifest.CompletedChunkIndexes.Any(index => index < 0) ||
            manifest.CompletedChunkIndexes.Distinct().Count() != manifest.CompletedChunkIndexes.Count)
            throw new InvalidDataException("Manifest chunk state is invalid.");

        if (manifest.Resource.AcceptsRanges && manifest.Resource.TotalLength > 0)
        {
            int rangeCount;
            try
            {
                rangeCount = RangePartition.Count(manifest.Resource.TotalLength, manifest.ChunkSizeBytes);
            }
            catch (ArgumentOutOfRangeException exception)
            {
                throw new InvalidDataException("Manifest range plan is invalid or exceeds the tracked chunk limit.", exception);
            }
            catch (OverflowException exception)
            {
                throw new InvalidDataException("Manifest range plan is too large.", exception);
            }

            if (manifest.CompletedChunkIndexes.Any(index => index >= rangeCount))
                throw new InvalidDataException("Manifest contains an out-of-range completed chunk.");
        }
        else if (manifest.CompletedChunkIndexes.Count > 0)
            throw new InvalidDataException("A sequential download cannot contain completed range chunks.");
    }
}
