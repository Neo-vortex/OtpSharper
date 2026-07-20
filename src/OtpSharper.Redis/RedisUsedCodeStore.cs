using OtpSharper.Abstractions;
using StackExchange.Redis;

namespace OtpSharper.Redis;

/// <summary>
/// Redis-backed <see cref="IUsedCodeStore"/> for multi-instance deployments, where
/// <see cref="UsedCodeTracker"/>'s per-process state isn't shared across servers.
/// </summary>
/// <remarks>
/// Each (keyId, counter) pair maps to a single Redis key, marked used via <c>SET ... NX EX</c> —
/// an atomic "set only if it doesn't already exist, with an expiry" in one round trip, so two
/// concurrent servers racing to mark the same code used can't both observe "first use". The
/// expiry (<paramref name="maxAge">maxAge</paramref> in the constructor) frees the key once the
/// code could no longer be valid anyway, mirroring <see cref="UsedCodeTracker"/>'s own cleanup.
/// </remarks>
public sealed class RedisUsedCodeStore : IUsedCodeStore
{
    private readonly IConnectionMultiplexer _connection;
    private readonly TimeSpan _maxAge;
    private readonly string _keyPrefix;

    /// <summary>Creates a Redis-backed replay tracker.</summary>
    /// <param name="connection">An existing, already-connected Redis multiplexer.</param>
    /// <param name="maxAge">
    /// How long a "used" marker is kept before Redis expires it. Should be at least as long as
    /// (windowSteps * stepSeconds * 2), same guidance as <see cref="UsedCodeTracker"/>.
    /// Default: 90 seconds.
    /// </param>
    /// <param name="keyPrefix">
    /// Prefix applied to every Redis key this store creates, to avoid collisions with other
    /// data in the same Redis instance. Default: <c>"otpsharper:used:"</c>.
    /// </param>
    public RedisUsedCodeStore(
        IConnectionMultiplexer connection,
        TimeSpan? maxAge = null,
        string keyPrefix = "otpsharper:used:")
    {
        _connection = connection ?? throw new ArgumentNullException(nameof(connection));
        _maxAge = maxAge ?? TimeSpan.FromSeconds(90);
        _keyPrefix = keyPrefix ?? throw new ArgumentNullException(nameof(keyPrefix));
    }

    private IDatabase Database => _connection.GetDatabase();

    /// <inheritdoc />
    public async ValueTask<bool> TryMarkUsedAsync(string keyId, long counter, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);

        // SET key value NX EX maxAge — atomic "only if absent" with a built-in expiry.
        bool firstUse = await Database
            .StringSetAsync(BuildKey(keyId, counter), "1", _maxAge, When.NotExists)
            .ConfigureAwait(false);
        return firstUse;
    }

    /// <inheritdoc />
    public async ValueTask<bool> IsUsedAsync(string keyId, long counter, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        return await Database.KeyExistsAsync(BuildKey(keyId, counter)).ConfigureAwait(false);
    }

    private RedisKey BuildKey(string keyId, long counter) => new($"{_keyPrefix}{keyId}:{counter}");
}
