using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SshSpeedDownloader.Transport.IdentityProviders;

public static class DeviceRequestCanonicalizer
{
    private const string Domain = "MODI-AUTH-DEVICE-V1";
    private const int MaximumBodyBytes = 16 * 1024;
    private const int MaximumTargetLength = 8192;
    private const string UriPunctuation = "/-._~!$&'()*+,;=:@?";
    private static readonly Regex TokenPattern = new("^[A-Za-z0-9_-]{1,128}$", RegexOptions.CultureInvariant);
    private static readonly Regex MethodPattern = new("^[A-Za-z]{1,16}$", RegexOptions.CultureInvariant);

    public static byte[] Create(
        string method,
        string requestTarget,
        ReadOnlySpan<byte> rawBody,
        string nonce,
        long unixTimestamp)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce);
        if (!MethodPattern.IsMatch(method))
            throw new ArgumentException("HTTP method is invalid.", nameof(method));
        if (rawBody.Length > MaximumBodyBytes)
            throw new ArgumentException("Request body is too large.", nameof(rawBody));
        if (!TokenPattern.IsMatch(nonce))
            throw new ArgumentException("Authorization nonce is invalid.", nameof(nonce));
        if (unixTimestamp < 0)
            throw new ArgumentOutOfRangeException(nameof(unixTimestamp));

        var normalizedTarget = NormalizeRequestTarget(requestTarget);
        var bodyHash = Convert.ToHexString(SHA256.HashData(rawBody)).ToLowerInvariant();
        var canonical = string.Join("\n",
            Domain,
            method.ToUpperInvariant(),
            normalizedTarget,
            bodyHash,
            nonce,
            unixTimestamp.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return Encoding.UTF8.GetBytes(canonical);
    }

    private static string NormalizeRequestTarget(string requestTarget)
    {
        if (string.IsNullOrEmpty(requestTarget) ||
            requestTarget.Length > MaximumTargetLength ||
            !requestTarget.StartsWith("/", StringComparison.Ordinal) ||
            requestTarget.StartsWith("//", StringComparison.Ordinal) ||
            requestTarget.Contains('#') ||
            requestTarget.Any(character => character is < (char)0x21 or > (char)0x7e))
            throw new ArgumentException("HTTP request target is invalid.", nameof(requestTarget));

        var queryIndex = requestTarget.IndexOf('?');
        var rawPath = queryIndex < 0 ? requestTarget : requestTarget[..queryIndex];
        var path = NormalizeEscapes(rawPath, rejectEncodedSeparators: true);
        if (path.Split('/').Any(IsDotSegment))
            throw new ArgumentException("Dot path segments are not allowed.", nameof(requestTarget));
        if (queryIndex < 0)
            return path;

        var rawQuery = requestTarget[(queryIndex + 1)..];
        if (rawQuery.Length == 0)
            return path + "?";
        var components = rawQuery.Split('&');
        if (components.Any(string.IsNullOrEmpty))
            throw new ArgumentException("Empty query components are not allowed.", nameof(requestTarget));
        return path + "?" + string.Join("&",
            components.Select(component => NormalizeEscapes(component, rejectEncodedSeparators: false))
                .Order(StringComparer.Ordinal));
    }

    private static string NormalizeEscapes(string value, bool rejectEncodedSeparators)
    {
        var result = new StringBuilder(value.Length);
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (character != '%')
            {
                if (!char.IsAsciiLetterOrDigit(character) && !UriPunctuation.Contains(character))
                    throw new ArgumentException("Request target contains an invalid URI character.", nameof(value));
                result.Append(character);
                continue;
            }

            if (index + 2 >= value.Length ||
                !TryHex(value[index + 1], out var high) ||
                !TryHex(value[index + 2], out var low))
                throw new ArgumentException("Request target contains an invalid percent escape.", nameof(value));
            var decoded = (high << 4) | low;
            if (rejectEncodedSeparators && decoded is '/' or '\\')
                throw new ArgumentException("Encoded path separators are not allowed.", nameof(value));
            result.Append('%');
            result.Append(value[index + 1].ToString().ToUpperInvariant());
            result.Append(value[index + 2].ToString().ToUpperInvariant());
            index += 2;
        }
        return result.ToString();
    }

    private static bool IsDotSegment(string segment)
    {
        var decoded = segment.Replace("%2E", ".", StringComparison.OrdinalIgnoreCase);
        return decoded is "." or "..";
    }

    private static bool TryHex(char value, out int digit)
    {
        if (value is >= '0' and <= '9')
        {
            digit = value - '0';
            return true;
        }
        if (value is >= 'a' and <= 'f')
        {
            digit = value - 'a' + 10;
            return true;
        }
        if (value is >= 'A' and <= 'F')
        {
            digit = value - 'A' + 10;
            return true;
        }
        digit = 0;
        return false;
    }
}
