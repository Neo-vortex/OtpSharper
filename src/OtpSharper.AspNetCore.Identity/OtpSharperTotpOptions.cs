using OtpSharper.Abstractions;
using OtpSharper.Totp;

namespace OtpSharper.AspNetCore.Identity;

/// <summary>
/// Configuration for <see cref="OtpSharperTotpTokenProvider{TUser}"/>.
/// </summary>
public sealed class OtpSharperTotpOptions
{
    /// <summary>
    /// TOTP algorithm/digits/window configuration used to generate and validate codes.
    /// Default: <see cref="TotpOptions.GoogleAuthenticator"/> (SHA1, 30s, 6 digits, ±1 step) —
    /// the same defaults Identity's built-in authenticator provider uses, for drop-in compatibility
    /// with existing enrolled authenticator apps. Set a stronger preset (e.g.
    /// <see cref="TotpOptions.HighSecurity"/>) only if you control enrollment end-to-end, since
    /// most authenticator apps assume SHA1/30s/6-digit.
    /// </summary>
    public TotpOptions TotpOptions { get; set; } = TotpOptions.GoogleAuthenticator;

    /// <summary>
    /// Optional replay-attack tracker. When set, a code that has already been accepted once
    /// for a given user cannot be accepted again within the validation window — closing the
    /// gap where a validation window wider than one step would otherwise let an intercepted
    /// code be replayed. Null (default) disables replay tracking.
    /// </summary>
    /// <remarks>
    /// Accepts any <see cref="IUsedCodeStore"/> — pass a <see cref="UsedCodeTracker"/> for a
    /// single-instance deployment, or <c>RedisUsedCodeStore</c> (from the <c>OtpSharper.Redis</c>
    /// package) for a distributed one, since <see cref="UsedCodeTracker"/>'s state is per-process.
    /// </remarks>
    public IUsedCodeStore? ReplayTracker { get; set; }
}
