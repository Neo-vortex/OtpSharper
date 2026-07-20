using System.Security.Cryptography;
using System.Text;
using OtpSharper.Core;

namespace OtpSharper.OutOfBand;

/// <summary>
/// Generates and validates random, single-use, short-lived numeric codes for
/// out-of-band delivery channels (SMS, email) — as opposed to <see cref="Totp.TotpGenerator"/>
/// / <see cref="Hotp.HotpGenerator"/>, which derive codes from a shared secret both
/// sides already hold.
/// </summary>
/// <remarks>
/// <para>
/// There is no shared secret here: the server generates a random code, remembers only
/// its hash via <see cref="IOobCodeStore"/>, and sends the plaintext out-of-band. A
/// successful <see cref="ValidateAsync"/> call consumes the code — it cannot be reused,
/// unlike a TOTP code which stays valid for its whole window.
/// </para>
/// <para>Thread-safety depends on the supplied <see cref="IOobCodeStore"/> implementation.</para>
/// </remarks>
/// <example>
/// <code>
/// var store     = new InMemoryOobCodeStore();
/// var generator = new OobCodeGenerator(store);
///
/// string code = await generator.GenerateAsync("phone:+15551234567");
/// // hand `code` to your SMS provider — it is not retrievable again
///
/// var result = await generator.ValidateAsync("phone:+15551234567", userInput);
/// if (result.IsValid) { /* proceed */ }
/// </code>
/// </example>
public sealed class OobCodeGenerator
{
    private readonly IOobCodeStore _store;
    private readonly OobCodeOptions _options;

    /// <summary>Creates an out-of-band code generator backed by the given store.</summary>
    /// <param name="store">Where pending (hashed) codes are persisted.</param>
    /// <param name="options">Digit count, TTL, and attempt-limit configuration. Null = defaults.</param>
    public OobCodeGenerator(IOobCodeStore store, OobCodeOptions? options = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _options = options ?? new OobCodeOptions();
        _options.Validate();
    }

    // ── Generation ────────────────────────────────────────────────────────────

    /// <summary>
    /// Generates a new random numeric code for <paramref name="key"/>, persists its hash,
    /// and returns the plaintext code so the caller can deliver it out-of-band.
    /// </summary>
    /// <param name="key">
    /// Identifier the code is bound to — typically the destination address
    /// (e.g. <c>"email:alice@example.com"</c>) or a per-request ID. Any existing
    /// pending code for this key is overwritten.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The plaintext code. This is the only time it is available — it is not stored.</returns>
    public async ValueTask<string> GenerateAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        string code = GenerateNumericCode(_options.Digits);
        string hash = Convert.ToHexString(ComputeHash(key, code));
        var stored = new OobStoredCode(hash, DateTimeOffset.UtcNow.Add(_options.Ttl), Attempts: 0);

        await _store.SaveAsync(key, stored, cancellationToken).ConfigureAwait(false);
        return code;
    }

    // ── Validation ────────────────────────────────────────────────────────────

    /// <summary>
    /// Validates a user-supplied code against the pending code for <paramref name="key"/>.
    /// On success, the pending code is consumed and cannot be validated again.
    /// On failure, the attempt counter is incremented; once <see cref="OobCodeOptions.MaxAttempts"/>
    /// is exceeded the pending code is invalidated and a new one must be requested.
    /// </summary>
    public async ValueTask<OtpValidationResult> ValidateAsync(
        string key, string userCode, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        OobStoredCode? stored = await _store.GetAsync(key, cancellationToken).ConfigureAwait(false);
        if (stored is null)
            return OtpValidationResult.Failure("No pending code for this key. Request a new one.");

        if (DateTimeOffset.UtcNow >= stored.ExpiresAt)
        {
            await _store.RemoveAsync(key, cancellationToken).ConfigureAwait(false);
            return OtpValidationResult.Failure("Code has expired. Request a new one.");
        }

        if (stored.Attempts >= _options.MaxAttempts)
        {
            await _store.RemoveAsync(key, cancellationToken).ConfigureAwait(false);
            return OtpValidationResult.Failure("Too many failed attempts. Request a new one.");
        }

        string normalised = (userCode ?? string.Empty).Trim();
        bool wellFormed = normalised.Length == _options.Digits;

        bool match = wellFormed
            && CryptographicOperations.FixedTimeEquals(
                ComputeHash(key, normalised),
                Convert.FromHexString(stored.CodeHash));

        if (!match)
        {
            await _store.SaveAsync(key, stored with { Attempts = stored.Attempts + 1 }, cancellationToken)
                .ConfigureAwait(false);
            return OtpValidationResult.Failure(
                wellFormed ? "Code did not match." : $"Expected {_options.Digits} digits.");
        }

        // One-time use: consume on success.
        await _store.RemoveAsync(key, cancellationToken).ConfigureAwait(false);
        return OtpValidationResult.Success(matchedCounter: 0, windowOffset: 0, matchedCode: normalised);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string GenerateNumericCode(int digits)
    {
        // Rejection sampling avoids the modulo bias a plain `byte % 10` would introduce
        // (256 isn't a multiple of 10, so digits 0-5 would be very slightly more likely).
        const int maxUnbiased = 250; // largest multiple of 10 that fits in a byte
        Span<char> result = stackalloc char[digits];
        Span<byte> randomByte = stackalloc byte[1];
        for (int i = 0; i < digits; i++)
        {
            do { RandomNumberGenerator.Fill(randomByte); }
            while (randomByte[0] >= maxUnbiased);
            result[i] = (char)('0' + randomByte[0] % 10);
        }
        return new string(result);
    }

    private static byte[] ComputeHash(string key, string code)
        => SHA256.HashData(Encoding.UTF8.GetBytes($"{key}\u0000{code}"));
}
