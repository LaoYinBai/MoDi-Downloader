using System.Buffers.Binary;

namespace SshSpeedDownloader.Desktop.Services;

internal static class CompletionSoundClip
{
    public static byte[] WithVolume(ReadOnlySpan<byte> source, int volumePercent)
    {
        if (source.Length is < 44 or > 262_144 ||
            !source[..4].SequenceEqual("RIFF"u8) || !source.Slice(8, 8).SequenceEqual("WAVEfmt "u8) ||
            BinaryPrimitives.ReadInt32LittleEndian(source[16..]) != 16 ||
            BinaryPrimitives.ReadUInt16LittleEndian(source[20..]) != 1 ||
            BinaryPrimitives.ReadUInt16LittleEndian(source[22..]) != 1 ||
            BinaryPrimitives.ReadUInt16LittleEndian(source[34..]) != 16 ||
            !source.Slice(36, 4).SequenceEqual("data"u8) ||
            BinaryPrimitives.ReadInt32LittleEndian(source[40..]) != source.Length - 44 ||
            (source.Length - 44) % 2 != 0)
            throw new InvalidDataException("The packaged completion clip is not supported PCM audio.");

        var result = source.ToArray();
        var gain = Math.Clamp(volumePercent, 0, 100) / 100d;
        for (var offset = 44; offset < result.Length; offset += 2)
        {
            var sample = BinaryPrimitives.ReadInt16LittleEndian(result.AsSpan(offset));
            BinaryPrimitives.WriteInt16LittleEndian(result.AsSpan(offset), (short)(sample * gain));
        }
        return result;
    }
}
