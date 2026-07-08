using System.Runtime.CompilerServices;

namespace OtpSharper.Core;

/// <summary>
/// RFC 4648 Base32 encoding and decoding.
/// Supports both standard (uppercase A-Z 2-7) and extended hex alphabets.
/// Padding characters are optional on decode.
/// </summary>
public static class Base32
{
    private const string StandardAlphabet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private const string HexAlphabet        = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    private const char   Padding            = '=';

    // Decode lookup tables (256 entries, -1 = invalid)
    private static readonly sbyte[] StandardLookup = BuildLookup(StandardAlphabet);
    private static readonly sbyte[] HexLookup      = BuildLookup(HexAlphabet);

    // ── Encoding ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Encodes a byte array to a Base32 string (uppercase, standard RFC 4648 alphabet).
    /// </summary>
    /// <param name="data">The bytes to encode.</param>
    /// <param name="padOutput">When <c>true</c>, output is padded with '=' to a multiple of 8.</param>
    /// <param name="hexAlphabet">When <c>true</c>, uses the extended hex alphabet (0-9A-V).</param>
    public static string Encode(ReadOnlySpan<byte> data, bool padOutput = true, bool hexAlphabet = false)
    {
        if (data.IsEmpty) return string.Empty;

        string alphabet = hexAlphabet ? HexAlphabet : StandardAlphabet;
        int outputLength = (data.Length * 8 + 4) / 5; // ceil(bits/5)
        int paddedLength = padOutput ? ((outputLength + 7) / 8) * 8 : outputLength;

        return string.Create(paddedLength, (data.ToArray(), alphabet, outputLength), static (span, state) =>
        {
            var (src, alpha, outLen) = state;
            int i = 0, idx = 0;
            int buffer = src[i++];
            int bitsLeft = 8;

            while (bitsLeft > 0 || i < src.Length)
            {
                if (bitsLeft < 5)
                {
                    if (i < src.Length)
                    {
                        buffer <<= 8;
                        buffer |= src[i++] & 0xFF;
                        bitsLeft += 8;
                    }
                    else
                    {
                        buffer <<= 5 - bitsLeft;
                        bitsLeft = 5;
                    }
                }
                bitsLeft -= 5;
                span[idx++] = alpha[(buffer >> bitsLeft) & 0x1F];
            }

            // Fill remaining with padding
            while (idx < span.Length)
                span[idx++] = '=';
        });
    }

    /// <summary>Encodes a byte array to a Base32 string.</summary>
    public static string Encode(byte[] data, bool padOutput = true, bool hexAlphabet = false)
        => Encode(data.AsSpan(), padOutput, hexAlphabet);

    // ── Decoding ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Decodes a Base32 string to bytes.
    /// </summary>
    /// <param name="base32">The Base32 string. Whitespace is ignored. Padding optional.</param>
    /// <param name="hexAlphabet">Use extended hex alphabet.</param>
    /// <exception cref="FormatException">Invalid Base32 character encountered.</exception>
    public static byte[] Decode(ReadOnlySpan<char> base32, bool hexAlphabet = false)
    {
        if (base32.IsEmpty) return [];

        sbyte[] lookup = hexAlphabet ? HexLookup : StandardLookup;

        // Strip whitespace and padding, convert to uppercase
        int cleanLen = 0;
        Span<char> clean = base32.Length <= 512
            ? stackalloc char[base32.Length]
            : new char[base32.Length];

        foreach (char c in base32)
        {
            if (char.IsWhiteSpace(c) || c == Padding) continue;
            clean[cleanLen++] = char.ToUpperInvariant(c);
        }

        clean = clean[..cleanLen];
        int outputBytes = cleanLen * 5 / 8;
        byte[] result = new byte[outputBytes];

        int buffer = 0, bitsLeft = 0, outIdx = 0;

        for (int i = 0; i < cleanLen; i++)
        {
            char ch = clean[i];
            if (ch >= 256 || lookup[ch] < 0)
                throw new FormatException($"Invalid Base32 character '{ch}' at position {i}.");

            buffer = (buffer << 5) | (byte)lookup[ch];
            bitsLeft += 5;

            if (bitsLeft < 8) continue;
            bitsLeft -= 8;
            result[outIdx++] = (byte)((buffer >> bitsLeft) & 0xFF);
        }

        return result;
    }

    /// <summary>Decodes a Base32 string to bytes.</summary>
    public static byte[] Decode(string base32, bool hexAlphabet = false)
        => Decode(base32.AsSpan(), hexAlphabet);

    /// <summary>
    /// Attempts to decode a Base32 string, returning false on failure rather than throwing.
    /// </summary>
    public static bool TryDecode(string base32, out byte[] bytes, bool hexAlphabet = false)
    {
        try
        {
            bytes = Decode(base32, hexAlphabet);
            return true;
        }
        catch
        {
            bytes = [];
            return false;
        }
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Generates a cryptographically random secret key encoded as Base32.
    /// </summary>
    /// <param name="byteLength">Secret byte length. Recommended: 20 (SHA1), 32 (SHA256), 64 (SHA512).</param>
    public static string GenerateSecret(int byteLength = 20)
    {
        byte[] bytes = new byte[byteLength];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return Encode(bytes, padOutput: false);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static sbyte[] BuildLookup(string alphabet)
    {
        var table = new sbyte[256];
        table.AsSpan().Fill(-1);
        for (int i = 0; i < alphabet.Length; i++)
            table[alphabet[i]] = (sbyte)i;
        return table;
    }
}
