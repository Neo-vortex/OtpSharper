using FluentAssertions;
using OtpSharper.Algorithms;
using OtpSharper.Core;
using OtpSharper.Totp;
using OtpSharper.Uri;
using Xunit;

namespace OtpSharper.Tests;

public class Base32Tests
{
    /// <summary>RFC 4648 test vectors.</summary>
    public static TheoryData<byte[], string> Rfc4648Vectors => new()
    {
        { ""u8.ToArray(),        ""          },
        { "f"u8.ToArray(),       "MY======"  },
        { "fo"u8.ToArray(),      "MZXQ===="  },
        { "foo"u8.ToArray(),     "MZXW6==="  },
        { "foob"u8.ToArray(),    "MZXW6YQ=" },
        { "fooba"u8.ToArray(),   "MZXW6YTB"  },
        { "foobar"u8.ToArray(),  "MZXW6YTBOI======" },
    };

    [Theory]
    [MemberData(nameof(Rfc4648Vectors))]
    public void Encode_MatchesRfc4648(byte[] input, string expected)
    {
        Base32.Encode(input, padOutput: true).Should().Be(expected);
    }

    [Theory]
    [MemberData(nameof(Rfc4648Vectors))]
    public void Decode_MatchesRfc4648(byte[] expected, string input)
    {
        if (input.Length == 0) return;
        Base32.Decode(input).Should().Equal(expected);
    }

    [Fact]
    public void RoundTrip_RandomBytes()
    {
        var random = new Random(42);
        for (int len = 1; len <= 64; len++)
        {
            byte[] data = new byte[len];
            random.NextBytes(data);
            string encoded = Base32.Encode(data);
            byte[] decoded = Base32.Decode(encoded);
            decoded.Should().Equal(data, $"round-trip failed for length {len}");
        }
    }

    [Fact]
    public void Decode_ToleratesLowercase()
    {
        Base32.Decode("mzxw6ytb").Should().Equal("fooba"u8.ToArray());
    }

    [Fact]
    public void Decode_ToleratesWhitespace()
    {
        Base32.Decode("MZXW 6YTB").Should().Equal("fooba"u8.ToArray());
    }

    [Fact]
    public void Decode_InvalidCharacter_Throws()
    {
        Action act = () => Base32.Decode("!@#$");
        act.Should().Throw<FormatException>();
    }

    [Fact]
    public void TryDecode_ReturnsFalseOnInvalid()
    {
        bool ok = Base32.TryDecode("!invalid!", out _);
        ok.Should().BeFalse();
    }

    [Fact]
    public void GenerateSecret_ProducesValidBase32()
    {
        string secret = Base32.GenerateSecret(20);
        secret.Should().NotBeEmpty();
        Base32.TryDecode(secret, out byte[] bytes).Should().BeTrue();
        bytes.Should().HaveCount(20);
    }
}

public class OtpUriTests
{
    [Fact]
    public void ToUriString_ProducesCorrectFormat()
    {
        using var secret = OtpSecret.FromBase32("JBSWY3DPEHPK3PXP");
        var uri = OtpUri.ForTotp("user@example.com", secret, issuer: "Example");

        string uriStr = uri.ToUriString();

        uriStr.Should().StartWith("otpauth://totp/");
        uriStr.Should().Contain("secret=");
        uriStr.Should().Contain("issuer=Example");
    }

    [Fact]
    public void Parse_RoundTrips()
    {
        using var secret = OtpSecret.FromBase32("JBSWY3DPEHPK3PXP");
        var original = OtpUri.ForTotp("alice@example.com", secret,
            new TotpOptions { Digits = 8, StepSeconds = 60, Algorithm = OtpAlgorithm.HmacSha256 },
            issuer: "MyApp");

        string uriStr = original.ToUriString();
        var parsed = OtpUri.Parse(uriStr);

        parsed.Label.Should().Be("alice@example.com");
        parsed.Issuer.Should().Be("MyApp");
        parsed.Digits.Should().Be(8);
        parsed.Period.Should().Be(60);
        parsed.Algorithm.Should().Be(OtpAlgorithm.HmacSha256);
        parsed.Secret.ToUpperInvariant().Should().Be("JBSWY3DPEHPK3PXP");
    }

    [Fact]
    public void Parse_StandardGoogleAuthUri()
    {
        const string uri = "otpauth://totp/Example%3Aalice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";

        var parsed = OtpUri.Parse(uri);

        parsed.Type.Should().Be(OtpUriType.Totp);
        parsed.Label.Should().Be("alice@google.com");
        parsed.Issuer.Should().Be("Example");
        parsed.Secret.Should().Be("JBSWY3DPEHPK3PXP");
        parsed.Algorithm.Should().Be(OtpAlgorithm.HmacSha1);
        parsed.Digits.Should().Be(6);
        parsed.Period.Should().Be(30);
    }

    [Fact]
    public void TryParse_ReturnsFalseOnInvalid()
    {
        bool ok = OtpUri.TryParse("not-a-uri", out var result, out string error);

        ok.Should().BeFalse();
        result.Should().BeNull();
        error.Should().NotBeEmpty();
    }

    [Fact]
    public void ToTotpGenerator_ProducesWorkingGenerator()
    {
        const string uri = "otpauth://totp/user@example.com?secret=JBSWY3DPEHPK3PXP";
        var parsed = OtpUri.Parse(uri);
        var generator = parsed.ToTotpGenerator();

        // Should generate a valid code
        string code = generator.Generate().Code;
        code.Should().MatchRegex(@"^\d{6}$");
        generator.Validate(code).IsValid.Should().BeTrue();
    }

    [Fact]
    [Obsolete("Obsolete")]
    public void QrCodeUrl_ContainsEncodedUri()
    {
        using var secret = OtpSecret.FromBase32("JBSWY3DPEHPK3PXP");
        var uri = OtpUri.ForTotp("user@example.com", secret);
        string qr = uri.ToQrCodeImageUrl(200);

        qr.Should().StartWith("https://chart.googleapis.com/chart?");
        qr.Should().Contain("200x200");
        qr.Should().Contain("otpauth");
    }
}

public class OtpSecretTests
{
    [Fact]
    public void FromBase32_RoundTrips()
    {
        const string base32 = "JBSWY3DPEHPK3PXP";
        using var secret = OtpSecret.FromBase32(base32);

        secret.ToBase32().ToUpperInvariant().Should().Be(base32);
    }

    [Fact]
    public void FromBase64_Works()
    {
        byte[] bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
        string b64 = Convert.ToBase64String(bytes);

        using var secret = OtpSecret.FromBase64(b64);
        secret.ToByteArray().Should().Equal(bytes);
    }

    [Fact]
    public void Generate_CreatesCorrectLength()
    {
        using var secret = OtpSecret.Generate(32);
        secret.Length.Should().Be(32);
    }

    [Fact]
    public void AfterDispose_ThrowsObjectDisposedException()
    {
        var secret = OtpSecret.Generate();
        secret.Dispose();

        Action act = () => secret.ToBase32();
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void EmptySecret_Throws()
    {
        Action act = () => _ = new OtpSecret(ReadOnlySpan<byte>.Empty);
        act.Should().Throw<ArgumentException>();
    }
}

public class OtpManagerTests
{
    [Fact]
    public void Create_GeneratesWorkingManager()
    {
        var manager = OtpManager.Create("user@example.com", issuer: "Test");

        string code = manager.Generate().Code;
        code.Should().MatchRegex(@"^\d{6}$");
        manager.Validate(code).Should().BeTrue();
    }

    [Fact]
    public void GetSetupKey_ReturnsBase32()
    {
        var manager = OtpManager.Create("user@example.com");
        string key = manager.GetSetupKey();

        key.Should().NotBeEmpty();
        Base32.TryDecode(key, out _).Should().BeTrue();
    }

    [Fact]
    public void GetOtpAuthUri_ContainsAllParts()
    {
        var manager = OtpManager.Create("user@example.com", issuer: "MyApp");
        string uri = manager.GetOtpAuthUri();

        uri.Should().StartWith("otpauth://totp/");
        uri.Should().Contain("MyApp");
        uri.Should().Contain("secret=");
    }

    [Fact]
    public void FromUri_RoundTrips()
    {
        var manager1 = OtpManager.Create("user@example.com", issuer: "App");
        string uri = manager1.GetOtpAuthUri();

        var manager2 = OtpManager.FromUri(uri);
        string code = manager1.Generate().Code;

        manager2.Validate(code).Should().BeTrue();
    }
}
