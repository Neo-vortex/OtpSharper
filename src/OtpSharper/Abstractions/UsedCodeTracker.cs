using System.Collections.Concurrent;

namespace OtpSharper.Abstractions;

/// <summary>
/// Abstraction for replay-attack tracking, so distributed backings (e.g. Redis) can be
/// swapped in for <see cref="UsedCodeTracker"/>'s in-memory, per-process default.
/// </summary>
/// <remarks>
/// <see cref="UsedCodeTracker"/> implements this interface, so any code written against
/// <see cref="IUsedCodeStore"/> works unchanged with either the in-memory default or a
/// distributed implementation such as <c>RedisUsedCodeStore</c> (in the <c>OtpSharper.Redis</c>
/// package).
/// </remarks>
public interface IUsedCodeStore
{
    /// <summary>
    /// Checks whether a (keyId, counter) pair has already been used, and marks it used if not.
    /// </summary>
    /// <returns>
    /// <c>true</c> if the code was freshly marked (first use) — proceed with login.
    /// <c>false</c> if this counter was already seen — reject as replay.
    /// </returns>
    ValueTask<bool> TryMarkUsedAsync(string keyId, long counter, CancellationToken cancellationToken = default);

    /// <summary>Checks whether a (keyId, counter) pair has already been used, without marking it.</summary>
    ValueTask<bool> IsUsedAsync(string keyId, long counter, CancellationToken cancellationToken = default);
}

/// <summary>
/// Tracks used OTP codes to prevent replay attacks within the validation window.
/// </summary>
/// <remarks>
/// <para>
/// Even with a small validation window (e.g., ±1 step), an attacker who intercepts a
/// valid TOTP code can replay it within the remaining step duration. This store
/// prevents such replays by recording which (keyId, counter) pairs have already
/// been accepted.
/// </para>
/// <para>
/// Thread-safe. Entries expire automatically after <c>maxAge</c>
/// (recommended: set to your full validation window duration).
/// For multi-server deployments, use <c>RedisUsedCodeStore</c> from the
/// <c>OtpSharper.Redis</c> package (or another <see cref="IUsedCodeStore"/> implementation)
/// instead — this class's state is per-process and not shared across servers.
/// </para>
/// </remarks>
public sealed class UsedCodeTracker : IUsedCodeStore
{
    private sealed record UsedEntry(DateTimeOffset UsedAt);
    private readonly ConcurrentDictionary<string, UsedEntry> _used = new();
    private readonly TimeSpan _maxAge;
    private DateTimeOffset _lastCleanup = DateTimeOffset.UtcNow;

    /// <summary>
    /// Creates a used-code tracker.
    /// </summary>
    /// <param name="maxAge">
    /// How long to remember a used code. Should be at least as long as
    /// (windowSteps * stepSeconds * 2). Default: 90 seconds (3 × 30s steps).
    /// </param>
    public UsedCodeTracker(TimeSpan? maxAge = null)
        => _maxAge = maxAge ?? TimeSpan.FromSeconds(90);

    /// <summary>
    /// Checks whether a (keyId, counter) pair has already been used,
    /// and marks it used if not.
    /// </summary>
    /// <param name="keyId">User/device identifier.</param>
    /// <param name="counter">The TOTP counter (time step) that produced the match.</param>
    /// <returns>
    /// <c>true</c> if the code was freshly marked (first use) — proceed with login.
    /// <c>false</c> if this counter was already seen — reject as replay.
    /// </returns>
    public bool TryMarkUsed(string keyId, long counter)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);

        MaybeCleanup();
        string key = $"{keyId}:{counter}";
        bool added = _used.TryAdd(key, new UsedEntry(DateTimeOffset.UtcNow));
        return added; // true = first use; false = replay
    }

    /// <summary>
    /// Checks whether a (keyId, counter) pair has already been used, without marking it.
    /// </summary>
    public bool IsUsed(string keyId, long counter)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        return _used.ContainsKey($"{keyId}:{counter}");
    }

    /// <summary>
    /// Forcibly clears all tracked entries (e.g., on restart).
    /// </summary>
    public void Reset() => _used.Clear();

    /// <summary>Number of currently tracked entries.</summary>
    public int Count => _used.Count;

    // ── IUsedCodeStore ────────────────────────────────────────────────────────

    /// <inheritdoc />
    ValueTask<bool> IUsedCodeStore.TryMarkUsedAsync(string keyId, long counter, CancellationToken cancellationToken)
        => ValueTask.FromResult(TryMarkUsed(keyId, counter));

    /// <inheritdoc />
    ValueTask<bool> IUsedCodeStore.IsUsedAsync(string keyId, long counter, CancellationToken cancellationToken)
        => ValueTask.FromResult(IsUsed(keyId, counter));

    // ── Private helpers ───────────────────────────────────────────────────────

    private void MaybeCleanup()
    {
        // Cleanup at most once per minute to amortize cost
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (now - _lastCleanup < TimeSpan.FromMinutes(1)) return;
        _lastCleanup = now;

        DateTimeOffset cutoff = now - _maxAge;
        foreach (var (key, entry) in _used)
        {
            if (entry.UsedAt < cutoff)
                _used.TryRemove(key, out _);
        }
    }
}
