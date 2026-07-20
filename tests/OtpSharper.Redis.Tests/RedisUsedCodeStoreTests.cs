using FluentAssertions;
using OtpSharper.Abstractions;
using Xunit;

namespace OtpSharper.Redis.Tests;

[Collection("Redis")]
public class RedisUsedCodeStoreTests(RedisFixture fixture)
{
    private RedisUsedCodeStore CreateStore()
        => new(fixture.Connection!, keyPrefix: $"otpsharper-test:{Guid.NewGuid():N}:");

    [Fact]
    public async Task TryMarkUsedAsync_FirstUse_ReturnsTrue()
    {
        if (!fixture.IsAvailable) return;

        var store = CreateStore();
        (await store.TryMarkUsedAsync("user1", 100)).Should().BeTrue();
    }

    [Fact]
    public async Task TryMarkUsedAsync_Replay_ReturnsFalse()
    {
        if (!fixture.IsAvailable) return;

        var store = CreateStore();
        await store.TryMarkUsedAsync("user1", 100);

        (await store.TryMarkUsedAsync("user1", 100)).Should().BeFalse();
    }

    [Fact]
    public async Task IsUsedAsync_ReflectsMarkedState()
    {
        if (!fixture.IsAvailable) return;

        var store = CreateStore();

        (await store.IsUsedAsync("user1", 55)).Should().BeFalse();
        await store.TryMarkUsedAsync("user1", 55);
        (await store.IsUsedAsync("user1", 55)).Should().BeTrue();
    }

    [Fact]
    public async Task DifferentCounters_BothAllowed()
    {
        if (!fixture.IsAvailable) return;

        var store = CreateStore();

        (await store.TryMarkUsedAsync("user1", 100)).Should().BeTrue();
        (await store.TryMarkUsedAsync("user1", 101)).Should().BeTrue();
    }

    [Fact]
    public async Task ConcurrentFirstUse_OnlyOneWinner()
    {
        if (!fixture.IsAvailable) return;

        // Two servers racing to mark the same code used — exactly one must see "first use".
        // This is the scenario the atomic SET NX EX in TryMarkUsedAsync exists for.
        IUsedCodeStore store = CreateStore();

        bool[] results = await Task.WhenAll(
            Enumerable.Range(0, 10).Select(_ => store.TryMarkUsedAsync("user1", 42).AsTask()));

        results.Count(r => r).Should().Be(1, "only the first racer should observe a fresh mark");
    }
}
