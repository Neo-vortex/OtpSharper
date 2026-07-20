using FluentAssertions;
using OtpSharper.Abstractions;
using OtpSharper.Core;
using OtpSharper.Totp;
using Xunit;

namespace OtpSharper.Tests;

public class BackoffPolicyTests
{
    [Fact]
    public void Fresh_Key_IsAllowed()
    {
        var policy = new OtpBackoffPolicy();
        var result = policy.CheckAllowed("user1");

        result.IsAllowed.Should().BeTrue();
        result.IsLockedOut.Should().BeFalse();
        result.RemainingAttempts.Should().Be(5);
    }

    [Fact]
    public void LockedOut_AfterMaxFailures()
    {
        var policy = new OtpBackoffPolicy(new OtpBackoffOptions { MaxFailedAttempts = 3 });

        policy.RecordFailure("user1");
        policy.RecordFailure("user1");
        var last = policy.RecordFailure("user1");

        last.IsLockedOut.Should().BeTrue();
        last.LockoutExpiry.Should().BeAfter(DateTimeOffset.UtcNow);
        policy.IsLockedOut("user1").Should().BeTrue();
    }

    [Fact]
    public void CheckAllowed_ReturnsFalse_WhenLockedOut()
    {
        var policy = new OtpBackoffPolicy(new OtpBackoffOptions { MaxFailedAttempts = 1 });
        policy.RecordFailure("user1");

        var result = policy.CheckAllowed("user1");
        result.IsAllowed.Should().BeFalse();
        result.IsLockedOut.Should().BeTrue();
    }

    [Fact]
    public void RecordSuccess_ResetsFailures()
    {
        var policy = new OtpBackoffPolicy(new OtpBackoffOptions { MaxFailedAttempts = 3 });
        policy.RecordFailure("user1");
        policy.RecordFailure("user1");

        policy.RecordSuccess("user1");

        var result = policy.CheckAllowed("user1");
        result.IsAllowed.Should().BeTrue();
        result.FailedAttempts.Should().Be(0);
    }

    [Fact]
    public void Unlock_ClearsLockout()
    {
        var policy = new OtpBackoffPolicy(new OtpBackoffOptions { MaxFailedAttempts = 1 });
        policy.RecordFailure("user1");
        policy.IsLockedOut("user1").Should().BeTrue();

        policy.Unlock("user1");

        policy.IsLockedOut("user1").Should().BeFalse();
    }

    [Fact]
    public void DifferentKeys_AreIndependent()
    {
        var policy = new OtpBackoffPolicy(new OtpBackoffOptions { MaxFailedAttempts = 1 });
        policy.RecordFailure("user1");

        policy.IsLockedOut("user2").Should().BeFalse();
        policy.CheckAllowed("user2").IsAllowed.Should().BeTrue();
    }
}

public class UsedCodeTrackerTests
{
    [Fact]
    public void FirstUse_ReturnsTrue()
    {
        var tracker = new UsedCodeTracker();
        bool result = tracker.TryMarkUsed("user1", counter: 100);

        result.Should().BeTrue();
    }

    [Fact]
    public void SecondUse_SameCounter_ReturnsFalse()
    {
        var tracker = new UsedCodeTracker();
        tracker.TryMarkUsed("user1", counter: 100);

        bool replay = tracker.TryMarkUsed("user1", counter: 100);

        replay.Should().BeFalse();
    }

    [Fact]
    public void DifferentCounters_BothAllowed()
    {
        var tracker = new UsedCodeTracker();

        tracker.TryMarkUsed("user1", 100).Should().BeTrue();
        tracker.TryMarkUsed("user1", 101).Should().BeTrue();
    }

    [Fact]
    public void DifferentUsers_SameCounter_BothAllowed()
    {
        var tracker = new UsedCodeTracker();

        tracker.TryMarkUsed("user1", 100).Should().BeTrue();
        tracker.TryMarkUsed("user2", 100).Should().BeTrue();
    }

    [Fact]
    public void IsUsed_ReturnsTrueAfterMark()
    {
        var tracker = new UsedCodeTracker();
        tracker.TryMarkUsed("user1", 55);

        tracker.IsUsed("user1", 55).Should().BeTrue();
        tracker.IsUsed("user1", 56).Should().BeFalse();
    }

    [Fact]
    public void Reset_ClearsAll()
    {
        var tracker = new UsedCodeTracker();
        tracker.TryMarkUsed("user1", 1);
        tracker.Reset();

        tracker.TryMarkUsed("user1", 1).Should().BeTrue();
        tracker.Count.Should().Be(1);
    }
}

public class UsedCodeStoreInterfaceTests
{
    // UsedCodeTracker implements IUsedCodeStore explicitly (see Abstractions/UsedCodeTracker.cs) so
    // that RedisUsedCodeStore (OtpSharper.Redis) is a drop-in substitute for distributed deployments.
    // These tests exercise it through the interface, not the concrete sync API covered above.

    [Fact]
    public async Task TryMarkUsedAsync_FirstUse_ReturnsTrue()
    {
        IUsedCodeStore store = new UsedCodeTracker();
        (await store.TryMarkUsedAsync("user1", 100)).Should().BeTrue();
    }

    [Fact]
    public async Task TryMarkUsedAsync_Replay_ReturnsFalse()
    {
        IUsedCodeStore store = new UsedCodeTracker();
        await store.TryMarkUsedAsync("user1", 100);

        (await store.TryMarkUsedAsync("user1", 100)).Should().BeFalse();
    }

    [Fact]
    public async Task IsUsedAsync_ReflectsMarkedState()
    {
        IUsedCodeStore store = new UsedCodeTracker();

        (await store.IsUsedAsync("user1", 55)).Should().BeFalse();
        await store.TryMarkUsedAsync("user1", 55);
        (await store.IsUsedAsync("user1", 55)).Should().BeTrue();
    }



    [Theory]
    [InlineData(OtpSharper.Algorithms.OtpAlgorithm.HmacSha1,   20)]
    [InlineData(OtpSharper.Algorithms.OtpAlgorithm.HmacSha256, 32)]
    [InlineData(OtpSharper.Algorithms.OtpAlgorithm.HmacSha512, 64)]
    public void GenerateForAlgorithm_ReturnsCorrectLength(
        OtpSharper.Algorithms.OtpAlgorithm algorithm, int expectedBytes)
    {
        using var secret = OtpSecretGenerator.GenerateForAlgorithm(algorithm);
        secret.Length.Should().Be(expectedBytes);
    }

    [Fact]
    public void AssessStrength_Weak_For10Bytes()
    {
        using var secret = OtpSecret.Generate(10);
        string b32 = secret.ToBase32();
        OtpSecretGenerator.AssessStrength(b32).Should().Be(SecretStrength.Weak);
    }

    [Fact]
    public void AssessStrength_Strong_For20Bytes()
    {
        using var secret = OtpSecret.Generate(20);
        string b32 = secret.ToBase32();
        OtpSecretGenerator.AssessStrength(b32).Should().Be(SecretStrength.Strong);
    }

    [Fact]
    public void EnsureMinimumStrength_Throws_ForWeakSecret()
    {
        using var secret = OtpSecret.Generate(5); // 40 bits
        string b32 = secret.ToBase32();

        Action act = () => OtpSecretGenerator.EnsureMinimumStrength(b32, minimumBits: 128);
        act.Should().Throw<System.Security.Cryptography.CryptographicException>();
    }

    [Fact]
    public void EnsureMinimumStrength_DoesNotThrow_ForStrongSecret()
    {
        using var secret = OtpSecret.Generate(32); // 256 bits
        string b32 = secret.ToBase32();

        Action act = () => OtpSecretGenerator.EnsureMinimumStrength(b32, minimumBits: 128);
        act.Should().NotThrow();
    }
}

public class TotpValidationServiceTests
{
    [Fact]
    public void Validate_Base32_AcceptsCurrentCode()
    {
        using var secret = OtpSecret.Generate();
        string b32 = secret.ToBase32();

        var service = new TotpValidationService();
        string code = service.Generate(b32).Code;

        service.Validate(b32, code).IsValid.Should().BeTrue();
    }

    [Fact]
    public void Validate_RawBytes_AcceptsCurrentCode()
    {
        using var secret = OtpSecret.Generate();
        byte[] bytes = secret.ToByteArray();

        var service = new TotpValidationService();
        string code = service.Generate(bytes).Code;

        service.Validate(bytes, code).IsValid.Should().BeTrue();
    }

    [Fact]
    public void Service_WithCustomOptions()
    {
        var service = new TotpValidationService(b => b
            .WithDigits(8)
            .WithAlgorithm(OtpSharper.Algorithms.OtpAlgorithm.HmacSha256));

        service.Options.Digits.Should().Be(8);
        service.Options.Algorithm.Should().Be(OtpSharper.Algorithms.OtpAlgorithm.HmacSha256);
    }
}
