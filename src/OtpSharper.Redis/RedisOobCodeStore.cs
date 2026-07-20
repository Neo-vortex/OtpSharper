using OtpSharper.OutOfBand;
using StackExchange.Redis;

namespace OtpSharper.Redis;

/// <summary>
/// Redis-backed <see cref="IOobCodeStore"/> for multi-instance deployments, where
/// <see cref="InMemoryOobCodeStore"/>'s per-process state isn't shared across servers.
/// </summary>
/// <remarks>
/// <para>
/// Each pending code is stored as a Redis hash (<c>hash</c>, <c>expiresAt</c>, <c>attempts</c>
/// fields) under <c>{keyPrefix}{key}</c>, with a Redis-native <c>EXPIRE</c> set to match
/// <see cref="OobStoredCode.ExpiresAt"/>. That gives you two independent expiry checks — Redis
/// will evict the entry on its own even if <see cref="OobCodeGenerator"/> never calls back to
/// remove it, and the generator's own expiry check still applies to whatever it reads.
/// </para>
/// <para>
/// <see cref="SaveAsync"/> overwrites the whole entry (hash, expiry, and attempt count) on
/// every call, matching how <see cref="OobCodeGenerator"/> uses it — it never needs a partial
/// update. This does mean two concurrent <c>SaveAsync</c> calls for the same key race normally
/// (last write wins), same as <see cref="InMemoryOobCodeStore"/> under its lock.
/// </para>
/// </remarks>
public sealed class RedisOobCodeStore : IOobCodeStore
{
    private readonly IConnectionMultiplexer _connection;
    private readonly string _keyPrefix;

    /// <summary>Creates a Redis-backed out-of-band code store.</summary>
    /// <param name="connection">An existing, already-connected Redis multiplexer.</param>
    /// <param name="keyPrefix">
    /// Prefix applied to every Redis key this store creates, to avoid collisions with other
    /// data in the same Redis instance. Default: <c>"otpsharper:oob:"</c>.
    /// </param>
    public RedisOobCodeStore(IConnectionMultiplexer connection, string keyPrefix = "otpsharper:oob:")
    {
        _connection = connection ?? throw new ArgumentNullException(nameof(connection));
        _keyPrefix = keyPrefix ?? throw new ArgumentNullException(nameof(keyPrefix));
    }

    private IDatabase Database => _connection.GetDatabase();

    /// <inheritdoc />
    public async ValueTask SaveAsync(string key, OobStoredCode code, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        ArgumentNullException.ThrowIfNull(code);

        TimeSpan ttl = code.ExpiresAt - DateTimeOffset.UtcNow;
        if (ttl <= TimeSpan.Zero)
        {
            // Already expired — nothing worth writing; also clears any stale prior entry.
            await RemoveAsync(key, cancellationToken).ConfigureAwait(false);
            return;
        }

        HashEntry[] entries =
        [
            new HashEntry("hash", code.CodeHash),
            new HashEntry("expiresAt", code.ExpiresAt.ToUnixTimeMilliseconds()),
            new HashEntry("attempts", code.Attempts),
        ];

        RedisKey redisKey = BuildKey(key);
        IBatch batch = Database.CreateBatch();
        Task setTask = batch.HashSetAsync(redisKey, entries);
        Task expireTask = batch.KeyExpireAsync(redisKey, ttl);
        batch.Execute();
        await Task.WhenAll(setTask, expireTask).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<OobStoredCode?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        HashEntry[] entries = await Database.HashGetAllAsync(BuildKey(key)).ConfigureAwait(false);
        if (entries.Length == 0)
            return null;

        string? hash = null;
        long? expiresAtMs = null;
        int? attempts = null;

        foreach (HashEntry entry in entries)
        {
            switch ((string)entry.Name!)
            {
                case "hash":      hash = (string)entry.Value!; break;
                case "expiresAt": expiresAtMs = (long)entry.Value; break;
                case "attempts":  attempts = (int)entry.Value; break;
            }
        }

        if (hash is null || expiresAtMs is null || attempts is null)
            return null; // corrupt/partial entry — treat as absent rather than throwing

        return new OobStoredCode(hash, DateTimeOffset.FromUnixTimeMilliseconds(expiresAtMs.Value), attempts.Value);
    }

    /// <inheritdoc />
    public async ValueTask RemoveAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        await Database.KeyDeleteAsync(BuildKey(key)).ConfigureAwait(false);
    }

    private RedisKey BuildKey(string key) => new(_keyPrefix + key);
}
