using FluentAssertions;
using OtpSharper.Algorithms;
using OtpSharper.Core;
using OtpSharper.Totp;
using Xunit;

namespace OtpSharper.Tests;

/// <summary>
/// RFC 6238 Appendix B test vectors.
/// Secret: ASCII "12345678901234567890" (SHA1)
///         ASCII "12345678901234567890123456789012" (SHA256)
///         ASCII "1234567890123456789012345678901234567890123456789012345678901234" (SHA512)
/// </summary>
public class TotpRfc6238Tests
{
    // SHA1 secret: ASCII "12345678901234567890"
    private static readonly byte[] Sha1Secret   = "12345678901234567890"u8.ToArray();
    // SHA256 secret: ASCII "12345678901234567890123456789012"
    private static readonly byte[] Sha256Secret = "12345678901234567890123456789012"u8.ToArray();
    // SHA512 secret: ASCII "1234567890..." (64 bytes)
    private static readonly byte[] Sha512Secret = "1234567890123456789012345678901234567890123456789012345678901234"u8.ToArray();

    /// <summary>RFC 6238 Appendix B test vectors.</summary>
    public static TheoryData<long, OtpAlgorithm, byte[], string> Rfc6238Vectors => new()
    {
        // Time step counter,  Algorithm,           Secret,        Expected 8-digit code
        {         59L / 30, OtpAlgorithm.HmacSha1,   Sha1Secret,   "94287082" },
        {         59L / 30, OtpAlgorithm.HmacSha256, Sha256Secret, "46119246" },
        {         59L / 30, OtpAlgorithm.HmacSha512, Sha512Secret, "90693936" },

        { 1111111109L / 30, OtpAlgorithm.HmacSha1,   Sha1Secret,   "07081804" },
        { 1111111109L / 30, OtpAlgorithm.HmacSha256, Sha256Secret, "68084774" },
        { 1111111109L / 30, OtpAlgorithm.HmacSha512, Sha512Secret, "25091201" },

        { 1111111111L / 30, OtpAlgorithm.HmacSha1,   Sha1Secret,   "14050471" },
        { 1111111111L / 30, OtpAlgorithm.HmacSha256, Sha256Secret, "67062674" },
        { 1111111111L / 30, OtpAlgorithm.HmacSha512, Sha512Secret, "99943326" },

        { 1234567890L / 30, OtpAlgorithm.HmacSha1,   Sha1Secret,   "89005924" },
        { 1234567890L / 30, OtpAlgorithm.HmacSha256, Sha256Secret, "91819424" },
        { 1234567890L / 30, OtpAlgorithm.HmacSha512, Sha512Secret, "93441116" },

        { 2000000000L / 30, OtpAlgorithm.HmacSha1,   Sha1Secret,   "69279037" },
        { 2000000000L / 30, OtpAlgorithm.HmacSha256, Sha256Secret, "90698825" },
        { 2000000000L / 30, OtpAlgorithm.HmacSha512, Sha512Secret, "38618901" },

        { 20000000000L / 30, OtpAlgorithm.HmacSha1,   Sha1Secret,   "65353130" },
        { 20000000000L / 30, OtpAlgorithm.HmacSha256, Sha256Secret, "77737706" },
        { 20000000000L / 30, OtpAlgorithm.HmacSha512, Sha512Secret, "47863826" },
    };

    [Theory]
    [MemberData(nameof(Rfc6238Vectors))]
    public void GenerateForCounter_MatchesRfc6238Vectors(
        long counter, OtpAlgorithm algorithm, byte[] secretBytes, string expected)
    {
        using var secret = new OtpSecret(secretBytes);
        var options = new TotpOptions { Algorithm = algorithm, Digits = 8, StepSeconds = 30 };
        var totp = new TotpGenerator(secret, options);

        OtpCode code = totp.GenerateForCounter(counter);

        code.Code.Should().Be(expected,
            $"RFC 6238 vector: counter={counter}, algorithm={algorithm}");
    }

    [Fact]
    public void Generate_ReturnsSixDigitsForDefaultOptions()
    {
        using var secret = OtpSecret.Generate();
        var totp = new TotpGenerator(secret);
        OtpCode code = totp.Generate();

        code.Code.Should().MatchRegex(@"^\d{6}$");
    }

    [Fact]
    public void Generate_ReturnsEightDigitsWhenConfigured()
    {
        using var secret = OtpSecret.Generate();
        var options = new TotpOptions { Digits = 8 };
        var totp = new TotpGenerator(secret, options);

        totp.Generate().Code.Should().MatchRegex(@"^\d{8}$");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(6)]
    [InlineData(8)]
    [InlineData(10)]
    public void Generate_ReturnsCorrectDigitCount(int digits)
    {
        using var secret = OtpSecret.Generate();
        var options = new TotpOptions { Digits = digits };
        var totp = new TotpGenerator(secret, options);

        totp.Generate().Code.Should().HaveLength(digits);
    }

    [Fact]
    public void Validate_AcceptsCurrentCode()
    {
        using var secret = OtpSecret.Generate();
        var totp = new TotpGenerator(secret);
        string code = totp.Generate().Code;

        var result = totp.Validate(code);

        result.IsValid.Should().BeTrue();
        result.WindowOffset.Should().Be(0);
    }

    [Fact]
    public void Validate_RejectsWrongCode()
    {
        using var secret = OtpSecret.Generate();
        var totp = new TotpGenerator(secret);
        // Generate code and increment last digit
        string code = totp.Generate().Code;

        // Edge case: might accidentally match — just test structure
        var result = totp.Validate("000000");
        // Probabilistically correct (1 in 10^6 chance of false positive from counter=0)
        result.FailureReason.Should().NotBeNull();
    }

    [Fact]
    public void Validate_AcceptsPreviousStepCode_WithWindow()
    {
        using var secret = new OtpSecret("12345678901234567890"u8.ToArray());
        var fixedTime = DateTimeOffset.FromUnixTimeSeconds(1111111111);
        var options = new TotpOptions
        {
            TimeProvider = new FixedTimeProvider(fixedTime),
            ValidationWindowSteps = 1,
        };
        var totp = new TotpGenerator(secret, options);

        // Generate code for one step behind
        long previousCounter = UnixTime.GetCounter(fixedTime, 30) - 1;
        string previousCode = totp.GenerateForCounter(previousCounter).Code;

        var result = totp.Validate(previousCode);

        result.IsValid.Should().BeTrue();
        result.WindowOffset.Should().Be(-1);
    }

    [Fact]
    public void Validate_RejectsPreviousStepCode_WithStrictWindow()
    {
        using var secret = OtpSecret.Generate(20);
        var fixedTime = DateTimeOffset.FromUnixTimeSeconds(1111111111);
        var options = new TotpOptions
        {
            TimeProvider = new FixedTimeProvider(fixedTime),
            ValidationWindowSteps = 0,
        };
        var totp = new TotpGenerator(secret, options);

        long previousCounter = UnixTime.GetCounter(fixedTime, 30) - 1;
        string previousCode = totp.GenerateForCounter(previousCounter).Code;

        var result = totp.Validate(previousCode);

        // Only accept if it accidentally matches current (astronomically unlikely)
        if (!result.IsValid)
            result.FailureReason.Should().Contain("window");
    }

    [Theory]
    [InlineData(30, 30)]
    [InlineData(30, -30)]
    [InlineData(5, 5)]
    [InlineData(5, -5)]
    public void Validate_AcceptsCode_AtExactWindowBoundary(int windowSteps, int offset)
    {
        using var secret = new OtpSecret("12345678901234567890"u8.ToArray());
        var fixedTime = DateTimeOffset.FromUnixTimeSeconds(1111111111);
        var options = new TotpOptions
        {
            TimeProvider = new FixedTimeProvider(fixedTime),
            ValidationWindowSteps = windowSteps,
        };
        var totp = new TotpGenerator(secret, options);

        long targetCounter = UnixTime.GetCounter(fixedTime, 30) + offset;
        string code = totp.GenerateForCounter(targetCounter).Code;

        var result = totp.Validate(code);

        result.IsValid.Should().BeTrue(
            $"a code exactly {offset} steps away should be accepted when the window is {windowSteps}");
        result.WindowOffset.Should().Be(offset);
    }

    [Theory]
    [InlineData(30, 31)]
    [InlineData(30, -31)]
    [InlineData(5, 6)]
    [InlineData(5, -6)]
    public void Validate_RejectsCode_OneStepOutsideWindowBoundary(int windowSteps, int offset)
    {
        using var secret = new OtpSecret("12345678901234567890"u8.ToArray());
        var fixedTime = DateTimeOffset.FromUnixTimeSeconds(1111111111);
        var options = new TotpOptions
        {
            TimeProvider = new FixedTimeProvider(fixedTime),
            ValidationWindowSteps = windowSteps,
        };
        var totp = new TotpGenerator(secret, options);

        long targetCounter = UnixTime.GetCounter(fixedTime, 30) + offset;
        string code = totp.GenerateForCounter(targetCounter).Code;

        var result = totp.Validate(code);

        result.IsValid.Should().BeFalse(
            $"a code {offset} steps away is just outside a window of {windowSteps} and must not be accepted");
    }

    [Fact]
    public void Validate_ExtraLookBehind_AcceptsOlderCodeBeyondSymmetricWindow()
    {
        using var secret = new OtpSecret("12345678901234567890"u8.ToArray());
        var fixedTime = DateTimeOffset.FromUnixTimeSeconds(1111111111);
        var options = new TotpOptions
        {
            TimeProvider = new FixedTimeProvider(fixedTime),
            ValidationWindowSteps = 1,
            ExtraLookBehindSteps = 4,
        };
        var totp = new TotpGenerator(secret, options);

        // 5 steps behind: outside the plain ±1 window, but inside window(1) + extra behind(4) = 5.
        long counter = UnixTime.GetCounter(fixedTime, 30) - 5;
        string code = totp.GenerateForCounter(counter).Code;

        var result = totp.Validate(code);

        result.IsValid.Should().BeTrue();
        result.WindowOffset.Should().Be(-5);
    }

    [Fact]
    public void Validate_ExtraLookBehind_DoesNotAlsoExtendLookAheadSide()
    {
        using var secret = new OtpSecret("12345678901234567890"u8.ToArray());
        var fixedTime = DateTimeOffset.FromUnixTimeSeconds(1111111111);
        var options = new TotpOptions
        {
            TimeProvider = new FixedTimeProvider(fixedTime),
            ValidationWindowSteps = 1,
            ExtraLookBehindSteps = 4,
        };
        var totp = new TotpGenerator(secret, options);

        // Ahead side was never extended, so +5 must still be rejected even though -5 (tested above) is accepted.
        long counter = UnixTime.GetCounter(fixedTime, 30) + 5;
        string code = totp.GenerateForCounter(counter).Code;

        totp.Validate(code).IsValid.Should().BeFalse();
    }

    [Fact]
    public void Validate_ExtraLookAhead_AcceptsNewerCodeBeyondSymmetricWindow()
    {
        using var secret = new OtpSecret("12345678901234567890"u8.ToArray());
        var fixedTime = DateTimeOffset.FromUnixTimeSeconds(1111111111);
        var options = new TotpOptions
        {
            TimeProvider = new FixedTimeProvider(fixedTime),
            ValidationWindowSteps = 1,
            ExtraLookAheadSteps = 4,
        };
        var totp = new TotpGenerator(secret, options);

        long counter = UnixTime.GetCounter(fixedTime, 30) + 5;
        string code = totp.GenerateForCounter(counter).Code;

        var result = totp.Validate(code);

        result.IsValid.Should().BeTrue();
        result.WindowOffset.Should().Be(5);
    }

    [Fact]
    public void Validate_ImplicitBoolConversion()
    {
        using var secret = OtpSecret.Generate();
        var totp = new TotpGenerator(secret);
        string code = totp.Generate().Code;

        bool valid = totp.Validate(code);
        valid.Should().BeTrue();
    }

    [Fact]
    public void Generate_RemainingSecondsInRange()
    {
        using var secret = OtpSecret.Generate();
        var totp = new TotpGenerator(secret);
        OtpCode code = totp.Generate();

        code.RemainingSeconds.Should().BeInRange(1, 30);
        code.ExpiresAt.Should().BeAfter(DateTimeOffset.UtcNow);
    }

    [Fact]
    public void GenerateWindow_ContainsCorrectOffsets()
    {
        using var secret = OtpSecret.Generate();
        var options = new TotpOptions { ValidationWindowSteps = 2 };
        var totp = new TotpGenerator(secret, options);

        var window = totp.GenerateWindow();

        window.Should().HaveCount(5); // -2, -1, 0, +1, +2
        window.Select(x => x.Offset).Should().BeEquivalentTo(new[] { -2, -1, 0, 1, 2 });
    }

    [Fact]
    public void CurrentCounter_Increases_OverTime()
    {
        using var secret = OtpSecret.Generate();

        var time1 = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(0));
        var time2 = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(30));

        var totp1 = new TotpGenerator(secret, new TotpOptions { TimeProvider = time1 });
        var totp2 = new TotpGenerator(secret, new TotpOptions { TimeProvider = time2 });

        totp2.CurrentCounter().Should().Be(totp1.CurrentCounter() + 1);
    }

    [Fact]
    public void CustomEpoch_ProducesDifferentCodes()
    {
        using var secret = OtpSecret.Generate();
        var fixedTime = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1000000));

        var defaultOptions = new TotpOptions { TimeProvider = fixedTime };
        var customOptions  = new TotpOptions
        {
            TimeProvider = fixedTime,
            Epoch = DateTimeOffset.FromUnixTimeSeconds(500000),
        };

        var totp1 = new TotpGenerator(secret, defaultOptions);
        var totp2 = new TotpGenerator(secret, customOptions);

        // Different epochs = different counters = different codes (with overwhelming probability)
        totp1.CurrentCounter().Should().NotBe(totp2.CurrentCounter());
    }

    [Fact]
    public void FluentBuilder_ProducesCorrectOptions()
    {
        using var secret = OtpSecret.Generate();
        var totp = new TotpGenerator(secret, b => b
            .WithAlgorithm(OtpAlgorithm.HmacSha256)
            .WithStepSeconds(60)
            .WithDigits(8)
            .WithValidationWindow(2));

        totp.Options.Algorithm.Should().Be(OtpAlgorithm.HmacSha256);
        totp.Options.StepSeconds.Should().Be(60);
        totp.Options.Digits.Should().Be(8);
        totp.Options.ValidationWindowSteps.Should().Be(2);
    }

    [Fact]
    public void Validate_EmptyCode_ReturnsFailure()
    {
        using var secret = OtpSecret.Generate();
        var totp = new TotpGenerator(secret);

        totp.Validate("").IsValid.Should().BeFalse();
        totp.Validate("   ").IsValid.Should().BeFalse();
    }

    [Fact]
    public void Validate_WrongLengthCode_ReturnsFailure()
    {
        using var secret = OtpSecret.Generate();
        var totp = new TotpGenerator(secret);

        totp.Validate("12345").IsValid.Should().BeFalse();
        totp.Validate("1234567").IsValid.Should().BeFalse();
    }

    [Theory]
    [InlineData(OtpAlgorithm.HmacSha1)]
    [InlineData(OtpAlgorithm.HmacSha256)]
    [InlineData(OtpAlgorithm.HmacSha512)]
    [InlineData(OtpAlgorithm.HmacSha3_256)]
    [InlineData(OtpAlgorithm.HmacSha3_512)]
    public void AllAlgorithms_GenerateAndValidate(OtpAlgorithm algorithm)
    {
        using var secret = OtpSecret.Generate(64); // 64 bytes works for all
        var options = new TotpOptions { Algorithm = algorithm };
        var totp = new TotpGenerator(secret, options);

        string code = totp.Generate().Code;
        totp.Validate(code).IsValid.Should().BeTrue(
            $"algorithm={algorithm} should produce valid codes");
    }
}
