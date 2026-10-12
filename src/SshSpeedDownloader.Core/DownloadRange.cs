namespace SshSpeedDownloader.Core;

public readonly record struct DownloadRange(int Index, long Offset, long Length)
{
    public long EndExclusive => checked(Offset + Length);
}
