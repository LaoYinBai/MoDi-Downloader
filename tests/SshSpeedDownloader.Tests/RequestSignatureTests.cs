using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SshSpeedDownloader.Core;

namespace SshSpeedDownloader.Tests;

public sealed class RequestSignatureTests
{
    [Fact]
    public void DeviceCanonicalRequestMatchesSharedCrossLanguageVectorAndUsesDerSignature()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceNames()
            .Where(name => name.EndsWith("device-auth-v1-vectors.json", StringComparison.Ordinal))
            .Select(name => Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
            .Single(resource => resource is not null)!;
        using var document = JsonDocument.Parse(stream);
        var vector = document.RootElement.GetProperty("vectors").GetProperty("device");
        var body = Encoding.UTF8.GetBytes(vector.GetProperty("bodyUtf8").GetString()!);
        var canonical = DeviceRequestSigner.BuildCanonicalPayload(
            vector.GetProperty("method").GetString()!,
            vector.GetProperty("requestTarget").GetString()!,
            body,
            vector.GetProperty("nonce").GetString()!,
            vector.GetProperty("unixTimestamp").GetInt64());

        Assert.Equal(vector.GetProperty("canonicalUtf8").GetString(), Encoding.UTF8.GetString(canonical));
        Assert.Equal(vector.GetProperty("bodySha256").GetString(),
            Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant());

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var envelope = DeviceRequestSigner.Sign(
            key,
            vector.GetProperty("keyId").GetString()!,
            vector.GetProperty("challengeId").GetString()!,
            vector.GetProperty("nonce").GetString()!,
            vector.GetProperty("unixTimestamp").GetInt64(),
            vector.GetProperty("method").GetString()!,
            vector.GetProperty("requestTarget").GetString()!,
            body);

        Assert.Equal(vector.GetProperty("keyId").GetString(), envelope.KeyId);
        Assert.Equal(vector.GetProperty("challengeId").GetString(), envelope.ChallengeId);
        Assert.Equal(vector.GetProperty("nonce").GetString(), envelope.Nonce);
        Assert.Equal(vector.GetProperty("unixTimestamp").GetInt64(), envelope.UnixTimestamp);
        Assert.True(key.VerifyData(
            canonical,
            Convert.FromBase64String(envelope.SignatureBase64),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence));
    }

    [Fact]
    public void CanonicalRequestUppercasesMethodAndSortsQueryComponents()
    {
        var body = Encoding.UTF8.GetBytes("{}");
        var canonical = DeviceRequestSigner.BuildCanonicalPayload(
            "get",
            "/v1/devices?z=last&a=first",
            body,
            "nonce-1",
            1791892800);

        Assert.Equal(
            "MODI-AUTH-DEVICE-V1\nGET\n/v1/devices?a=first&z=last\n" +
            Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant() +
            "\nnonce-1\n1791892800",
            Encoding.UTF8.GetString(canonical));
    }
}
