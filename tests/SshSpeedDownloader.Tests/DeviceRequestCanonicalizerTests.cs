using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using SshSpeedDownloader.Transport.IdentityProviders;

namespace SshSpeedDownloader.Tests;

public sealed class DeviceRequestCanonicalizerTests
{
    [Fact]
    public void MatchesTheSharedDeviceAuthorizationSignatureVector()
    {
        const string body = "{\"idempotencyKey\":\"vector-request-01\"}";
        const string expected =
            "MODI-AUTH-DEVICE-V1\n" +
            "POST\n" +
            "/v1/access-requests\n" +
            "867eb16eca21d508777234e89113d466b0a0e262ffd9017d034eef0cb32fd6bc\n" +
            "nonce-device-vector\n" +
            "1791892800";

        var canonical = DeviceRequestCanonicalizer.Create(
            "post",
            "/v1/access-requests",
            Encoding.UTF8.GetBytes(body),
            "nonce-device-vector",
            1791892800);

        Assert.Equal(expected, Encoding.UTF8.GetString(canonical));
    }

    [Fact]
    public void SharedServiceSignatureVectorVerifiesWithCanonicalizedBytes()
    {
        const string body = "{\"idempotencyKey\":\"vector-request-01\"}";
        const string publicKey =
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBB86Yd0/1itpQGlH0UO71kgeVvGheBgm3FZDj45oqxfSoUS7vOLMBr+NSqqCnbR9Y/kl4b0yiOhkfhO9LPAavCA= vector-device";
        const string signatureBase64 =
            "MEYCIQCDH+KRnFZ2p9eXuTMFwxIbn9HUF0p1kQ7PjX4CPoDu+gIhANFjyi4Axgz5VQzMjX5Izlr49vUrO4J8z9JthS8IdvTy";
        var canonical = DeviceRequestCanonicalizer.Create(
            "post",
            "/v1/access-requests",
            Encoding.UTF8.GetBytes(body),
            "nonce-device-vector",
            1791892800);
        using var verifier = ImportOpenSshP256PublicKey(publicKey);

        Assert.True(verifier.VerifyData(
            canonical,
            Convert.FromBase64String(signatureBase64),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence));
    }

    [Fact]
    public void NormalizesPercentEscapesAndSortsQueryComponents()
    {
        var canonical = DeviceRequestCanonicalizer.Create(
            "GET",
            "/v1/access-requests/0123456789abcdef0123456789abcdef?z=%2f&a=1",
            Array.Empty<byte>(),
            "nonce-1",
            1791892800);

        Assert.Contains(
            "\n/v1/access-requests/0123456789abcdef0123456789abcdef?a=1&z=%2F\n",
            Encoding.UTF8.GetString(canonical));
    }

    [Theory]
    [InlineData("relative/path")]
    [InlineData("//other-host/path")]
    [InlineData("/v1/%2fadmin")]
    [InlineData("/v1/../admin")]
    [InlineData("/v1/%2e%2E/admin")]
    [InlineData("/v1/path?x=1&")]
    [InlineData("/v1/path?x=1&&y=2")]
    [InlineData("/v1/bad%escape")]
    public void RejectsAmbiguousRequestTargets(string target)
    {
        Assert.Throws<ArgumentException>(() => DeviceRequestCanonicalizer.Create(
            "GET",
            target,
            Array.Empty<byte>(),
            "nonce-1",
            1791892800));
    }

    private static ECDsa ImportOpenSshP256PublicKey(string publicKey)
    {
        var fields = publicKey.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var blob = Convert.FromBase64String(fields[1]);
        var offset = 0;
        var algorithm = ReadSshString(blob, ref offset);
        var curve = ReadSshString(blob, ref offset);
        var point = ReadSshString(blob, ref offset);
        Assert.Equal("ecdsa-sha2-nistp256", Encoding.ASCII.GetString(algorithm));
        Assert.Equal("nistp256", Encoding.ASCII.GetString(curve));
        Assert.Equal(65, point.Length);
        Assert.Equal(4, point[0]);
        return ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = point.AsSpan(1, 32).ToArray(),
                Y = point.AsSpan(33, 32).ToArray()
            }
        });
    }

    private static byte[] ReadSshString(byte[] blob, ref int offset)
    {
        var length = BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(offset, 4));
        offset += 4;
        var value = blob.AsSpan(offset, (int)length).ToArray();
        offset += (int)length;
        return value;
    }
}
