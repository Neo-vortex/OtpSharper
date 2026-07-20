using FluentAssertions;
using Xunit;

namespace OtpSharper.Redis.Tests;

[Collection("Redis")]
public class RedisHotpCounterStoreTests(RedisFixture fixture)
{
    private RedisHotpCounterStore CreateStore()
        => new(fixture.Connection!, keyPrefix: $"otpsharper-test:{Guid.NewGuid():N}:");

    [Fact]
    public async Task GetCounterAsync_DefaultsToZero_ForUnknownKey()
    {
        if (!fixture.IsAvailable) return;

        var store = CreateStore();
        (await store.GetCounterAsync("user1")).Should().Be(0);
    }

    [Fact]
    public async Task SetThenGet_RoundTrips()
    {
        if (!fixture.IsAvailable) return;

        var store = CreateStore();
        await store.SetCounterAsync("user1", 5);

        (await store.GetCounterAsync("user1")).Should().Be(5);
    }

    [Fact]
    public async Task SetCounterAsync_DoesNotRegress()
    {
        if (!fixture.IsAvailable) return;

        var store = CreateStore();
        await store.SetCounterAsync("user1", 10);
        await store.SetCounterAsync("user1", 3); // attempted regression — must be ignored

        (await store.GetCounterAsync("user1")).Should().Be(10,
            "the counter must never move backwards, even if a stale caller tries");
    }

    [Fact]
    public async Task SetCounterAsync_AdvancesOnStrictlyGreaterValue()
    {
        if (!fixture.IsAvailable) return;

        var store = CreateStore();
        await store.SetCounterAsync("user1", 10);
        await store.SetCounterAsync("user1", 11);

        (await store.GetCounterAsync("user1")).Should().Be(11);
    }

    [Fact]
    public async Task DifferentKeys_AreIndependent()
    {
        if (!fixture.IsAvailable) return;

        var store = CreateStore();
        await store.SetCounterAsync("user-a", 7);

        (await store.GetCounterAsync("user-b")).Should().Be(0);
    }

    [Fact]
    public async Task ConcurrentAdvances_NeverRegress()
    {
        if (!fixture.IsAvailable) return;

        // Simulates several server instances racing to advance the same counter — the Lua
        // script backing SetCounterAsync must keep the read-compare-write atomic even so.
        var store = CreateStore();
        var candidates = Enumerable.Range(1, 20).ToArray();

        await Task.WhenAll(candidates.Select(c => store.SetCounterAsync("user1", c).AsTask()));

        (await store.GetCounterAsync("user1")).Should().Be(candidates.Max());
    }
}
