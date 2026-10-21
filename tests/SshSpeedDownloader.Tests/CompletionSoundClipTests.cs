using System.Buffers.Binary;
using SshSpeedDownloader.Desktop.Services;

namespace SshSpeedDownloader.Tests;

public sealed class CompletionSoundClipTests
{
    [Fact]
    public void PackagedClipIsShortPcmAndFullVolumeDoesNotAlterIt()
    {
        var source = LoadClip();
        var result = CompletionSoundClip.WithVolume(source, 100);
        Assert.Equal(source, result);
        Assert.InRange((source.Length - 44d) / 88_200, 0.2, 0.7);
        Assert.Equal(44_100, BinaryPrimitives.ReadInt32LittleEndian(source.AsSpan(24)));
    }

    [Fact]
    public void MuteAndHalfVolumePreserveHeaderAndNeverModifyOriginal()
    {
        var source = LoadClip();
        var original = source.ToArray();
        var muted = CompletionSoundClip.WithVolume(source, -10);
        var half = CompletionSoundClip.WithVolume(source, 50);
        Assert.Equal(original, source);
        Assert.Equal(source[..44], muted[..44]);
        Assert.All(muted.Skip(44), value => Assert.Equal(0, value));
        for (var offset = 44; offset < source.Length; offset += 2)
            Assert.Equal((short)(BinaryPrimitives.ReadInt16LittleEndian(source.AsSpan(offset)) * 0.5),
                BinaryPrimitives.ReadInt16LittleEndian(half.AsSpan(offset)));
        Assert.Equal(source, CompletionSoundClip.WithVolume(source, 110));
    }

    [Fact]
    public void TruncatedOrUnexpectedWaveFormatFailsSafely()
    {
        Assert.Throws<InvalidDataException>(() => CompletionSoundClip.WithVolume([1, 2, 3], 55));
        var source = LoadClip();
        source[20] = 3;
        Assert.Throws<InvalidDataException>(() => CompletionSoundClip.WithVolume(source, 55));
    }

    private static byte[] LoadClip()
    {
        using var stream = typeof(CompletionSoundClipTests).Assembly.GetManifestResourceStream("Test.Completion.wav")!;
        using var bytes = new MemoryStream();
        stream.CopyTo(bytes);
        return bytes.ToArray();
    }
}
