using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Tests;

public sealed class SafeInputTests
{
    [Theory]
    [InlineData("https://example.com/file.zip?token=secret&part=3", "https://example.com/file.zip?redacted")]
    [InlineData("https://example.com/a%20b.bin", "https://example.com/a%20b.bin")]
    public void RedactsQueryValuesBeforeLogging(string source, string expected)
    {
        Assert.Equal(expected, UrlSafety.RedactForLog(new Uri(source)));
    }

    [Theory]
    [InlineData("https://example.com/file.zip", true)]
    [InlineData("http://example.com/file", true)]
    [InlineData("ftp://example.com/file", false)]
    [InlineData("file:///C:/secret", false)]
    [InlineData("https://user:pass@example.com/file", false)]
    public void OnlyAcceptsCredentialFreeHttpAndHttpsUrls(string source, bool valid)
    {
        Assert.Equal(valid, UrlSafety.TryValidateDownloadUri(source, out _));
    }

    [Theory]
    [InlineData("../../outside.txt", "outside.txt")]
    [InlineData("CON.txt", "_CON.txt")]
    [InlineData("archive?.zip", "archive_.zip")]
    [InlineData("  file.txt. ", "file.txt")]
    public void ProducesSafeWindowsFileNames(string source, string expected)
    {
        Assert.Equal(expected, DownloadFileName.Sanitize(source));
    }
}
