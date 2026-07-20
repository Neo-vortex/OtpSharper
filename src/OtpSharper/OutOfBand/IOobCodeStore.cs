namespace OtpSharper.OutOfBand;

/// <summary>
/// A pending out-of-band code as persisted by an <see cref="IOobCodeStore"/>.
/// The plaintext code is never stored — only its hash.
/// </summary>
/// <param name="CodeHash">Hex-encoded SHA-256 hash of the code, salted with the store key.</param>
/// <param name="ExpiresAt">UTC time after which the code is no longer valid.</param>
/// <param name="Attempts">Number of failed validation attempts so far.</param>
public sealed record OobStoredCode(string CodeHash, DateTimeOffset ExpiresAt, int Attempts);

/// <summary>
/// Abstraction for persisting pending out-of-band (SMS/email) verification codes.
/// </summary>
/// <remarks>
/// Implementations must never receive or store the plaintext code — only the hash
/// computed by <see cref="OobCodeGenerator"/>. For multi-instance deployments,
/// back this with a shared store (Redis, database) rather than the in-memory default.
/// </remarks>
public interface IOobCodeStore
{
    /// <summary>Saves (or overwrites) the pending code state for <paramref name="key"/>.</summary>
    ValueTask SaveAsync(string key, OobStoredCode code, CancellationToken cancellationToken = default);

    /// <summary>Retrieves the pending code state for <paramref name="key"/>, or null if none exists.</summary>
    ValueTask<OobStoredCode?> GetAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>Removes any pending code state for <paramref name="key"/>.</summary>
    ValueTask RemoveAsync(string key, CancellationToken cancellationToken = default);
}

/// <summary>
/// Thread-safe in-memory <see cref="IOobCodeStore"/>.
/// </summary>
/// <remarks>
/// Suitable for development/testing and single-instance deployments only.
/// State is lost on restart and is not shared across processes.
/// </remarks>
public sealed class InMemoryOobCodeStore : IOobCodeStore
{
    private readonly Dictionary<string, OobStoredCode> _entries = [];
    private readonly Lock _lock = new();

    /// <inheritdoc />
    public ValueTask SaveAsync(string key, OobStoredCode code, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        ArgumentNullException.ThrowIfNull(code);
        lock (_lock) { _entries[key] = code; }
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask<OobStoredCode?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        lock (_lock)
        {
            return ValueTask.FromResult(_entries.GetValueOrDefault(key));
        }
    }

    /// <inheritdoc />
    public ValueTask RemoveAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        lock (_lock) { _entries.Remove(key); }
        return ValueTask.CompletedTask;
    }

    /// <summary>Number of currently tracked pending codes (for testing/diagnostics).</summary>
    public int Count { get { lock (_lock) { return _entries.Count; } } }
}
