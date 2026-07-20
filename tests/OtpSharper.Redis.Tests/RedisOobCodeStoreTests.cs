using FluentAssertions;
using OtpSharper.OutOfBand;
using Xunit;

namespace OtpSharper.Redis.Tests;

[Collection("Redis")]
public class RedisOobCodeStoreTests(RedisFixture fixture)
{
    private RedisOobCodeStore CreateStore()
        => new(fixture.Connection!, keyPrefix: $"otpsharper-test:{Guid.NewGuid():N}:");

    [Fact]
    public async Task SaveThenGet_RoundTrips()
    {
        if (!fixture.IsAvailable) return; // see RedisFixture remarks

        var store = CreateStore();
        var code = new OobStoredCode("deadbeef", DateTimeOffset.UtcNow.AddMinutes(5), Attempts: 2);

        await store.SaveAsync("user1", code);
        OobStoredCode? retrieved = await store.GetAsync("user1");

        retrieved.Should().Be(code);
    }

    [Fact]
    public async Task Get_ReturnsNull_ForUnknownKey()
    {
        if (!fixture.IsAvailable) return;

        var store = CreateStore();
        (await store.GetAsync("never-saved")).Should().BeNull();
    }

    [Fact]
    public async Task Remove_ClearsEntry()
    {
        if (!fixture.IsAvailable) return;

        var store = CreateStore();
        await store.SaveAsync("user1", new OobStoredCode("hash", DateTimeOffset.UtcNow.AddMinutes(5), 0));

        await store.RemoveAsync("user1");

        (await store.GetAsync("user1")).Should().BeNull();
    }

    [Fact]
    public async Task SaveAsync_AlreadyExpiredCode_IsNotStored()
    {
        if (!fixture.IsAvailable) return;

        var store = CreateStore();
        var expired = new OobStoredCode("hash", DateTimeOffset.UtcNow.AddSeconds(-1), 0);

        await store.SaveAsync("user1", expired);

        (await store.GetAsync("user1")).Should().BeNull();
    }

    [Fact]
    public async Task EndToEnd_ThroughOobCodeGenerator()
    {
        if (!fixture.IsAvailable) return;

        var generator = new OobCodeGenerator(CreateStore());

        string code = await generator.GenerateAsync("user1");
        var result = await generator.ValidateAsync("user1", code);

        result.IsValid.Should().BeTrue();

        // Second validation must fail — one-time use, and Redis is the source of truth here.
        (await generator.ValidateAsync("user1", code)).IsValid.Should().BeFalse();
    }
}
