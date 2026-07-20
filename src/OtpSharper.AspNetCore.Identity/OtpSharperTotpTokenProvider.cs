using Microsoft.AspNetCore.Identity;
using OtpSharper.Core;
using OtpSharper.Totp;

namespace OtpSharper.AspNetCore.Identity;

/// <summary>
/// <see cref="IUserTwoFactorTokenProvider{TUser}"/> implementation backed by
/// <see cref="TotpGenerator"/> — a drop-in alternative to ASP.NET Core Identity's built-in
/// <c>AuthenticatorTokenProvider</c> that additionally supports configurable HMAC algorithms,
/// digit counts, validation windows, and optional replay protection.
/// </summary>
/// <remarks>
/// <para>
/// Uses the same <c>IUserAuthenticatorKeyStore&lt;TUser&gt;</c>-backed key that
/// <see cref="UserManager{TUser}.GetAuthenticatorKeyAsync"/> /
/// <see cref="UserManager{TUser}.ResetAuthenticatorKeyAsync"/> already manage, so it plugs into
/// existing enrollment flows (<c>GenerateNewAuthenticatorKey</c> / QR-code setup pages) unchanged —
/// only the token provider registration changes.
/// </para>
/// <para>Register via <see cref="IdentityBuilderExtensions.AddOtpSharperTwoFactorTokenProvider{TUser}"/>.</para>
/// </remarks>
/// <example>
/// <code>
/// builder.Services.AddIdentity&lt;ApplicationUser, IdentityRole&gt;()
///     .AddEntityFrameworkStores&lt;ApplicationDbContext&gt;()
///     .AddOtpSharperTwoFactorTokenProvider&lt;ApplicationUser&gt;(options =>
///     {
///         options.TotpOptions = TotpOptions.HighSecurity; // SHA256, 8 digits, strict window
///     });
/// </code>
/// </example>
public sealed class OtpSharperTotpTokenProvider<TUser> : IUserTwoFactorTokenProvider<TUser>
    where TUser : class
{
    private readonly OtpSharperTotpOptions _options;

    /// <summary>Creates the token provider. Typically resolved via dependency injection.</summary>
    /// <param name="options">
    /// Shared configuration registered by <see cref="IdentityBuilderExtensions.AddOtpSharperTwoFactorTokenProvider{TUser}"/>.
    /// Null = <see cref="TotpOptions.GoogleAuthenticator"/> defaults, no replay tracking.
    /// </param>
    public OtpSharperTotpTokenProvider(OtpSharperTotpOptions? options = null)
        => _options = options ?? new OtpSharperTotpOptions();

    /// <inheritdoc />
    public async Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
    {
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentNullException.ThrowIfNull(user);

        if (!manager.SupportsUserAuthenticatorKey)
            return false;

        string? key = await manager.GetAuthenticatorKeyAsync(user).ConfigureAwait(false);
        return !string.IsNullOrEmpty(key);
    }

    /// <inheritdoc />
    public async Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user)
    {
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentNullException.ThrowIfNull(user);

        using OtpSecret secret = await GetSecretAsync(manager, user).ConfigureAwait(false);
        var totp = new TotpGenerator(secret, _options.TotpOptions);
        return totp.Generate().Code;
    }

    /// <inheritdoc />
    public async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
    {
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentNullException.ThrowIfNull(user);

        if (string.IsNullOrEmpty(token))
            return false;

        string? key = await manager.GetAuthenticatorKeyAsync(user).ConfigureAwait(false);
        if (string.IsNullOrEmpty(key))
            return false;

        using var secret = OtpSecret.FromBase32(key);
        var totp = new TotpGenerator(secret, _options.TotpOptions);
        OtpValidationResult result = totp.Validate(token);

        if (!result.IsValid)
            return false;

        if (_options.ReplayTracker is not null)
        {
            string userId = await manager.GetUserIdAsync(user).ConfigureAwait(false);
            // A code already accepted once for this user cannot be accepted again
            // within the window — prevents replay of an intercepted code.
            if (!await _options.ReplayTracker.TryMarkUsedAsync(userId, result.MatchedCounter).ConfigureAwait(false))
                return false;
        }

        return true;
    }

    private static async Task<OtpSecret> GetSecretAsync(UserManager<TUser> manager, TUser user)
    {
        string? key = await manager.GetAuthenticatorKeyAsync(user).ConfigureAwait(false);
        if (string.IsNullOrEmpty(key))
            throw new InvalidOperationException(
                "User has no authenticator key set. Call UserManager.ResetAuthenticatorKeyAsync first.");

        return OtpSecret.FromBase32(key);
    }
}
