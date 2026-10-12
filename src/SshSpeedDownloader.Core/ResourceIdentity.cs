namespace SshSpeedDownloader.Core;

public sealed record ResourceIdentity(
    long TotalLength,
    bool AcceptsRanges,
    string? EntityTag,
    DateTimeOffset? LastModifiedUtc)
{
    public string? ExpectedSha256 { get; init; }
}

public static class ResumeValidator
{
    public static bool CanResume(ResourceIdentity previous, ResourceIdentity current)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(current);

        if (!previous.AcceptsRanges || !current.AcceptsRanges || previous.TotalLength <= 0 ||
            previous.TotalLength != current.TotalLength)
            return false;
        if (previous.ExpectedSha256 is not null && current.ExpectedSha256 is not null &&
            !string.Equals(previous.ExpectedSha256, current.ExpectedSha256, StringComparison.Ordinal))
            return false;

        var oldStrongTag = StrongTag(previous.EntityTag);
        var newStrongTag = StrongTag(current.EntityTag);
        if (oldStrongTag is not null || newStrongTag is not null)
            return oldStrongTag is not null && string.Equals(oldStrongTag, newStrongTag, StringComparison.Ordinal);

        return previous.LastModifiedUtc is { } oldModified &&
               current.LastModifiedUtc is { } newModified && oldModified == newModified;
    }

    private static string? StrongTag(string? tag) =>
        string.IsNullOrWhiteSpace(tag) || tag.StartsWith("W/", StringComparison.OrdinalIgnoreCase) ? null : tag;
}
