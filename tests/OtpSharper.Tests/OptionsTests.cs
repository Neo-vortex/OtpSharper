using FluentAssertions;
using OtpSharper.Abstractions;
using OtpSharper.Algorithms;
using OtpSharper.Core;
using OtpSharper.Hotp;
using OtpSharper.OutOfBand;
using OtpSharper.Totp;
using Xunit;

namespace OtpSharper.Tests;

public class TotpOptionsTests
{
    [Fact]
    public void Defaults_MatchRfc6238()
    {
        var options = new TotpOptions();

        options.Algorithm.Should().Be(OtpAlgorithm.HmacSha1);
        options.StepSeconds.Should().Be(30);
        options.Digits.Should().Be(6);
        options.Epoch.Should().Be(DateTimeOffset.UnixEpoch);
        options.ValidationWindowSteps.Should().Be(1);
        options.ExtraLookBehindSteps.Should().Be(0);
        options.ExtraLookAheadSteps.Should().Be(0);
        options.UseConstantTimeComparison.Should().BeTrue();
    }

    [Fact]
    public void Default_Preset_IsEquivalentToDefaultConstructor()
    {
        var preset = TotpOptions.Default;

        preset.Algorithm.Should().Be(OtpAlgorithm.HmacSha1);
        preset.StepSeconds.Should().Be(30);
        preset.Digits.Should().Be(6);
        preset.ValidationWindowSteps.Should().Be(1);
    }

    [Fact]
    public void GoogleAuthenticator_Preset_Is30SecondsSixDigitsSha1()
    {
        var preset = TotpOptions.GoogleAuthenticator;

        preset.Algorithm.Should().Be(OtpAlgorithm.HmacSha1);
        preset.StepSeconds.Should().Be(30);
        preset.Digits.Should().Be(6);
        preset.ValidationWindowSteps.Should().Be(1);
    }

    [Fact]
    public void HighSecurity_Preset_Is8DigitsSha256Strict()
    {
        var preset = TotpOptions.HighSecurity;

        preset.Algorithm.Should().Be(OtpAlgorithm.HmacSha256);
        preset.StepSeconds.Should().Be(30);
        preset.Digits.Should().Be(8);
        preset.ValidationWindowSteps.Should().Be(0);
    }

    [Fact]
    public void MaxSecurity_Preset_Is8DigitsSha512Strict()
    {
        var preset = TotpOptions.MaxSecurity;

        preset.Algorithm.Should().Be(OtpAlgorithm.HmacSha512);
        preset.StepSeconds.Should().Be(30);
        preset.Digits.Should().Be(8);
        preset.ValidationWindowSteps.Should().Be(0);
    }

    [Fact]
    public void SixtySeconds_Preset_Is60SecondStep()
    {
        var preset = TotpOptions.SixtySeconds;

        preset.Algorithm.Should().Be(OtpAlgorithm.HmacSha1);
        preset.StepSeconds.Should().Be(60);
        preset.Digits.Should().Be(6);
        preset.ValidationWindowSteps.Should().Be(1);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3601)]
    [InlineData(-1)]
    public void Validate_Throws_ForOutOfRangeStepSeconds(int stepSeconds)
    {
        var options = new TotpOptions { StepSeconds = stepSeconds };

        Action act = options.Validate;
        act.Should().Throw<InvalidOperationException>().WithMessage("*StepSeconds*");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(11)]
    [InlineData(-1)]
    public void Validate_Throws_ForOutOfRangeDigits(int digits)
    {
        var options = new TotpOptions { Digits = digits };

        Action act = options.Validate;
        act.Should().Throw<InvalidOperationException>().WithMessage("*Digits*");
    }

    [Fact]
    public void Validate_Throws_ForNegativeValidationWindowSteps()
    {
        var options = new TotpOptions { ValidationWindowSteps = -1 };

        Action act = options.Validate;
        act.Should().Throw<InvalidOperationException>().WithMessage("*ValidationWindowSteps*");
    }

    [Fact]
    public void Validate_Throws_ForNegativeExtraLookBehindSteps()
    {
        var options = new TotpOptions { ExtraLookBehindSteps = -1 };

        Action act = options.Validate;
        act.Should().Throw<InvalidOperationException>().WithMessage("*ExtraLookBehindSteps*");
    }

    [Fact]
    public void Validate_Throws_ForNegativeExtraLookAheadSteps()
    {
        var options = new TotpOptions { ExtraLookAheadSteps = -1 };

        Action act = options.Validate;
        act.Should().Throw<InvalidOperationException>().WithMessage("*ExtraLookAheadSteps*");
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(3600, 10)]
    public void Validate_DoesNotThrow_ForBoundaryValues(int stepSeconds, int digits)
    {
        var options = new TotpOptions { StepSeconds = stepSeconds, Digits = digits };

        Action act = options.Validate;
        act.Should().NotThrow();
    }
}

public class HotpOptionsTests
{
    [Fact]
    public void Defaults_MatchRfc4226()
    {
        var options = new HotpOptions();

        options.Algorithm.Should().Be(OtpAlgorithm.HmacSha1);
        options.Digits.Should().Be(6);
        options.LookAheadWindow.Should().Be(5);
    }

    [Fact]
    public void Default_Preset_MatchesDefaultConstructor()
    {
        var preset = HotpOptions.Default;

        preset.Algorithm.Should().Be(OtpAlgorithm.HmacSha1);
        preset.Digits.Should().Be(6);
        preset.LookAheadWindow.Should().Be(5);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(11)]
    [InlineData(-1)]
    public void Validate_Throws_ForOutOfRangeDigits(int digits)
    {
        var options = new HotpOptions { Digits = digits };

        Action act = options.Validate;
        act.Should().Throw<InvalidOperationException>().WithMessage("*Digits*");
    }

    [Fact]
    public void Validate_Throws_ForNegativeLookAheadWindow()
    {
        var options = new HotpOptions { LookAheadWindow = -1 };

        Action act = options.Validate;
        act.Should().Throw<InvalidOperationException>().WithMessage("*LookAheadWindow*");
    }

    [Theory]
    [InlineData(1, 0)]
    [InlineData(10, 100)]
    public void Validate_DoesNotThrow_ForBoundaryValues(int digits, int lookAhead)
    {
        var options = new HotpOptions { Digits = digits, LookAheadWindow = lookAhead };

        Action act = options.Validate;
        act.Should().NotThrow();
    }
}

public class OobCodeOptionsTests
{
    [Fact]
    public void Defaults_AreSixDigitsFiveMinutesFiveAttempts()
    {
        var options = new OobCodeOptions();

        options.Digits.Should().Be(6);
        options.Ttl.Should().Be(TimeSpan.FromMinutes(5));
        options.MaxAttempts.Should().Be(5);
    }

    [Theory]
    [InlineData(3)]
    [InlineData(11)]
    public void Constructor_Throws_ForOutOfRangeDigits(int digits)
    {
        Action act = () => new OobCodeGenerator(new InMemoryOobCodeStore(), new OobCodeOptions { Digits = digits });
        act.Should().Throw<ArgumentOutOfRangeException>().Where(e => e.ParamName == "Digits");
    }

    [Theory]
    [InlineData(4)]
    [InlineData(10)]
    public void Constructor_DoesNotThrow_ForBoundaryDigits(int digits)
    {
        Action act = () => new OobCodeGenerator(new InMemoryOobCodeStore(), new OobCodeOptions { Digits = digits });
        act.Should().NotThrow();
    }

    [Fact]
    public void Constructor_Throws_ForNonPositiveTtl()
    {
        Action act = () => new OobCodeGenerator(new InMemoryOobCodeStore(), new OobCodeOptions { Ttl = TimeSpan.Zero });
        act.Should().Throw<ArgumentOutOfRangeException>().Where(e => e.ParamName == "Ttl");
    }

    [Fact]
    public void Constructor_Throws_ForZeroMaxAttempts()
    {
        Action act = () => new OobCodeGenerator(new InMemoryOobCodeStore(), new OobCodeOptions { MaxAttempts = 0 });
        act.Should().Throw<ArgumentOutOfRangeException>().Where(e => e.ParamName == "MaxAttempts");
    }
}

public class TotpOptionsBuilderTests
{
    [Fact]
    public void Build_WithNoConfiguration_MatchesDefault()
    {
        var options = new TotpOptionsBuilder().Build();

        options.Algorithm.Should().Be(TotpOptions.DefaultAlgorithm);
        options.StepSeconds.Should().Be(TotpOptions.DefaultStepSeconds);
        options.Digits.Should().Be(TotpOptions.DefaultDigits);
        options.ValidationWindowSteps.Should().Be(TotpOptions.DefaultWindowSteps);
    }

    [Fact]
    public void Build_AppliesAllFluentSetters()
    {
        var epoch = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var options = new TotpOptionsBuilder()
            .WithAlgorithm(OtpAlgorithm.HmacSha256)
            .WithStepSeconds(60)
            .WithDigits(8)
            .WithEpoch(epoch)
            .WithValidationWindow(2)
            .WithExtraLookBehind(3)
            .WithExtraLookAhead(4)
            .WithoutConstantTimeComparison()
            .Build();

        options.Algorithm.Should().Be(OtpAlgorithm.HmacSha256);
        options.StepSeconds.Should().Be(60);
        options.Digits.Should().Be(8);
        options.Epoch.Should().Be(epoch);
        options.ValidationWindowSteps.Should().Be(2);
        options.ExtraLookBehindSteps.Should().Be(3);
        options.ExtraLookAheadSteps.Should().Be(4);
        options.UseConstantTimeComparison.Should().BeFalse();
    }

    [Fact]
    public void AsGoogleAuthenticator_ConfiguresExpectedPreset()
    {
        var options = new TotpOptionsBuilder().AsGoogleAuthenticator().Build();

        options.Algorithm.Should().Be(OtpAlgorithm.HmacSha1);
        options.StepSeconds.Should().Be(30);
        options.Digits.Should().Be(6);
        options.ValidationWindowSteps.Should().Be(1);
    }

    [Fact]
    public void AsMicrosoftAuthenticator_ConfiguresExpectedPreset()
    {
        var options = new TotpOptionsBuilder().AsMicrosoftAuthenticator().Build();

        options.Algorithm.Should().Be(OtpAlgorithm.HmacSha1);
        options.StepSeconds.Should().Be(30);
        options.Digits.Should().Be(6);
        options.ValidationWindowSteps.Should().Be(1);
    }

    [Fact]
    public void AsHighSecurity_ConfiguresExpectedPreset()
    {
        var options = new TotpOptionsBuilder().AsHighSecurity().Build();

        options.Algorithm.Should().Be(OtpAlgorithm.HmacSha256);
        options.StepSeconds.Should().Be(30);
        options.Digits.Should().Be(8);
        options.ValidationWindowSteps.Should().Be(0);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3601)]
    public void WithStepSeconds_Throws_ForOutOfRangeValue(int seconds)
    {
        Action act = () => new TotpOptionsBuilder().WithStepSeconds(seconds);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(11)]
    public void WithDigits_Throws_ForOutOfRangeValue(int digits)
    {
        Action act = () => new TotpOptionsBuilder().WithDigits(digits);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void WithValidationWindow_Throws_ForNegativeValue()
    {
        Action act = () => new TotpOptionsBuilder().WithValidationWindow(-1);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void WithExtraLookBehind_Throws_ForNegativeValue()
    {
        Action act = () => new TotpOptionsBuilder().WithExtraLookBehind(-1);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void WithExtraLookAhead_Throws_ForNegativeValue()
    {
        Action act = () => new TotpOptionsBuilder().WithExtraLookAhead(-1);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void WithTimeProvider_Throws_ForNull()
    {
        Action act = () => new TotpOptionsBuilder().WithTimeProvider(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void WithValidationWindow30_ActuallyAcceptsAndRejectsAtTheBoundary()
    {
        // Proves the option isn't just stored on TotpOptions — it changes what Validate() accepts.
        using var secret = new OtpSecret("12345678901234567890"u8.ToArray());
        var fixedTime = DateTimeOffset.FromUnixTimeSeconds(1111111111);
        var totp = new TotpGenerator(secret, b => b
            .WithTimeProvider(new FixedTimeProvider(fixedTime))
            .WithValidationWindow(30));

        long currentCounter = UnixTime.GetCounter(fixedTime, 30);

        string codeAt30 = totp.GenerateForCounter(currentCounter + 30).Code;
        totp.Validate(codeAt30).IsValid.Should().BeTrue("30 steps away is inside a window of 30");

        string codeAt31 = totp.GenerateForCounter(currentCounter + 31).Code;
        totp.Validate(codeAt31).IsValid.Should().BeFalse("31 steps away is outside a window of 30");
    }

    [Fact]
    public void WithClockOffset_ShiftsGeneratedTime()
    {
        var options = new TotpOptionsBuilder()
            .WithClockOffset(TimeSpan.FromHours(1))
            .Build();

        DateTimeOffset before = DateTimeOffset.UtcNow;
        DateTimeOffset observed = options.TimeProvider.UtcNow;

        observed.Should().BeCloseTo(before + TimeSpan.FromHours(1), TimeSpan.FromSeconds(5));
    }
}

public class OtpBackoffOptionsTests
{
    [Fact]
    public void Defaults_MatchDocumentedValues()
    {
        var options = new OtpBackoffOptions();

        options.MaxFailedAttempts.Should().Be(5);
        options.LockoutDuration.Should().Be(TimeSpan.FromMinutes(15));
        options.AttemptWindow.Should().Be(TimeSpan.FromMinutes(10));
        options.ResetOnSuccess.Should().BeTrue();
    }

    [Fact]
    public void Properties_AreConfigurableViaObjectInitializer()
    {
        var options = new OtpBackoffOptions
        {
            MaxFailedAttempts = 3,
            LockoutDuration = TimeSpan.FromMinutes(1),
            AttemptWindow = TimeSpan.FromMinutes(2),
            ResetOnSuccess = false,
        };

        options.MaxFailedAttempts.Should().Be(3);
        options.LockoutDuration.Should().Be(TimeSpan.FromMinutes(1));
        options.AttemptWindow.Should().Be(TimeSpan.FromMinutes(2));
        options.ResetOnSuccess.Should().BeFalse();
    }
}
