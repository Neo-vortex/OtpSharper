using FluentAssertions;
using OtpSharper.OutOfBand;
using Xunit;

namespace OtpSharper.Tests;

public class OobCodeGeneratorTests
{
    [Fact]
    public async Task GenerateAsync_ProducesCodeOfConfiguredLength()
    {
        var generator = new OobCodeGenerator(new InMemoryOobCodeStore(), new OobCodeOptions { Digits = 6 });

        string code = await generator.GenerateAsync("user1");

        code.Should().HaveLength(6);
        code.Should().MatchRegex("^[0-9]{6}$");
    }

    [Fact]
    public async Task ValidateAsync_AcceptsCorrectCode()
    {
        var generator = new OobCodeGenerator(new InMemoryOobCodeStore());

        string code = await generator.GenerateAsync("user1");
        var result = await generator.ValidateAsync("user1", code);

        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateAsync_RejectsWrongCode()
    {
        var generator = new OobCodeGenerator(new InMemoryOobCodeStore());
        await generator.GenerateAsync("user1");

        var result = await generator.ValidateAsync("user1", "000000");

        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task ValidateAsync_RejectsWithoutAPendingCode()
    {
        var generator = new OobCodeGenerator(new InMemoryOobCodeStore());

        var result = await generator.ValidateAsync("never-requested", "123456");

        result.IsValid.Should().BeFalse();
        result.FailureReason.Should().Contain("No pending code");
    }

    [Fact]
    public async Task ValidateAsync_IsOneTimeUse()
    {
        var generator = new OobCodeGenerator(new InMemoryOobCodeStore());
        string code = await generator.GenerateAsync("user1");

        var first  = await generator.ValidateAsync("user1", code);
        var second = await generator.ValidateAsync("user1", code);

        first.IsValid.Should().BeTrue();
        second.IsValid.Should().BeFalse("the code was already consumed by the first validation");
    }

    [Fact]
    public async Task ValidateAsync_RejectsExpiredCode()
    {
        var generator = new OobCodeGenerator(
            new InMemoryOobCodeStore(),
            new OobCodeOptions { Ttl = TimeSpan.FromMilliseconds(1) });

        string code = await generator.GenerateAsync("user1");
        await Task.Delay(50); // let it expire

        var result = await generator.ValidateAsync("user1", code);

        result.IsValid.Should().BeFalse();
        result.FailureReason.Should().Contain("expired");
    }

    [Fact]
    public async Task ValidateAsync_LocksOutAfterMaxAttempts()
    {
        var generator = new OobCodeGenerator(
            new InMemoryOobCodeStore(),
            new OobCodeOptions { MaxAttempts = 2 });

        string code = await generator.GenerateAsync("user1");

        await generator.ValidateAsync("user1", "000000"); // attempt 1, wrong
        await generator.ValidateAsync("user1", "000000"); // attempt 2, wrong — now locked out

        var result = await generator.ValidateAsync("user1", code); // correct code, but too late
        result.IsValid.Should().BeFalse();
        result.FailureReason.Should().Contain("Too many failed attempts");
    }

    [Fact]
    public async Task ValidateAsync_StillAllowsCorrectCode_BelowMaxAttemptsThreshold()
    {
        var generator = new OobCodeGenerator(
            new InMemoryOobCodeStore(),
            new OobCodeOptions { MaxAttempts = 3 });

        string code = await generator.GenerateAsync("user1");

        await generator.ValidateAsync("user1", "000000"); // attempt 1, wrong
        await generator.ValidateAsync("user1", "000001"); // attempt 2, wrong — still below the threshold of 3

        var result = await generator.ValidateAsync("user1", code);
        result.IsValid.Should().BeTrue("only 2 of the allowed 3 attempts were consumed by wrong guesses");
    }

    [Fact]
    public async Task GenerateAsync_NewRequestOverwritesPreviousPendingCode()
    {
        var generator = new OobCodeGenerator(new InMemoryOobCodeStore());

        string firstCode = await generator.GenerateAsync("user1");
        string secondCode = await generator.GenerateAsync("user1");

        (await generator.ValidateAsync("user1", firstCode)).IsValid
            .Should().BeFalse("the first code was superseded by the second request");
        (await generator.ValidateAsync("user1", secondCode)).IsValid
            .Should().BeTrue("the second, most recent code is the one still pending");
    }

    [Fact]
    public async Task DifferentKeys_AreIndependent()
    {
        var generator = new OobCodeGenerator(new InMemoryOobCodeStore());

        string codeA = await generator.GenerateAsync("user-a");
        await generator.GenerateAsync("user-b");

        (await generator.ValidateAsync("user-a", codeA)).IsValid.Should().BeTrue();
    }

    [Fact]
    public void Constructor_RejectsOutOfRangeOptions()
    {
        Action act = () => new OobCodeGenerator(new InMemoryOobCodeStore(), new OobCodeOptions { Digits = 2 });
        act.Should().Throw<ArgumentOutOfRangeException>();
    }
}

public class InMemoryOobCodeStoreTests
{
    [Fact]
    public async Task SaveThenGet_RoundTrips()
    {
        var store = new InMemoryOobCodeStore();
        var code = new OobStoredCode("hash", DateTimeOffset.UtcNow.AddMinutes(5), Attempts: 0);

        await store.SaveAsync("key1", code);
        var retrieved = await store.GetAsync("key1");

        retrieved.Should().Be(code);
    }

    [Fact]
    public async Task Get_ReturnsNull_ForUnknownKey()
    {
        var store = new InMemoryOobCodeStore();
        (await store.GetAsync("missing")).Should().BeNull();
    }

    [Fact]
    public async Task Remove_ClearsEntry()
    {
        var store = new InMemoryOobCodeStore();
        await store.SaveAsync("key1", new OobStoredCode("hash", DateTimeOffset.UtcNow.AddMinutes(5), 0));

        await store.RemoveAsync("key1");

        (await store.GetAsync("key1")).Should().BeNull();
        store.Count.Should().Be(0);
    }
}
