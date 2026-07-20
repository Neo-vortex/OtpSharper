using OtpSharper.Hotp;
using StackExchange.Redis;

namespace OtpSharper.Redis;

/// <summary>
/// Redis-backed <see cref="IHotpCounterStore"/> for multi-instance deployments, where
/// <see cref="InMemoryHotpCounterStore"/>'s per-process state isn't shared across servers.
/// </summary>
/// <remarks>
/// <see cref="IHotpCounterStore.SetCounterAsync"/> requires that the counter only ever moves
/// forward, atomically, even under concurrent callers — a plain <c>GET</c> then <c>SET</c>
/// from .NET would race across two server instances. This implementation instead evaluates a
/// small Lua script server-side, so the read-compare-write happens as one atomic Redis
/// operation regardless of how many instances call it concurrently.
/// </remarks>
public sealed class RedisHotpCounterStore : IHotpCounterStore
{
    // KEYS[1] = counter key, ARGV[1] = candidate new counter value.
    // Only advances the stored value if the candidate is strictly greater — mirrors
    // InMemoryHotpCounterStore.SetCounterAsync's "no-op if newCounter <= current" contract.
    private const string AdvanceIfGreaterScript = """
        local current = tonumber(redis.call('GET', KEYS[1]) or '0')
        local candidate = tonumber(ARGV[1])
        if candidate > current then
            redis.call('SET', KEYS[1], ARGV[1])
        end
        return 1
        """;

    private readonly IConnectionMultiplexer _connection;
    private readonly string _keyPrefix;

    /// <summary>Creates a Redis-backed HOTP counter store.</summary>
    /// <param name="connection">An existing, already-connected Redis multiplexer.</param>
    /// <param name="keyPrefix">
    /// Prefix applied to every Redis key this store creates, to avoid collisions with other
    /// data in the same Redis instance. Default: <c>"otpsharper:hotp:"</c>.
    /// </param>
    public RedisHotpCounterStore(IConnectionMultiplexer connection, string keyPrefix = "otpsharper:hotp:")
    {
        _connection = connection ?? throw new ArgumentNullException(nameof(connection));
        _keyPrefix = keyPrefix ?? throw new ArgumentNullException(nameof(keyPrefix));
    }

    private IDatabase Database => _connection.GetDatabase();

    /// <inheritdoc />
    public async ValueTask<long> GetCounterAsync(string keyId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);

        RedisValue value = await Database.StringGetAsync(BuildKey(keyId)).ConfigureAwait(false);
        return value.IsNullOrEmpty ? 0L : (long)value;
    }

    /// <inheritdoc />
    public async ValueTask SetCounterAsync(string keyId, long newCounter, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);

        RedisKey[] keys = [BuildKey(keyId)];
        RedisValue[] args = [newCounter];
        await Database.ScriptEvaluateAsync(AdvanceIfGreaterScript, keys, args).ConfigureAwait(false);
    }

    private RedisKey BuildKey(string keyId) => new(_keyPrefix + keyId);
}
