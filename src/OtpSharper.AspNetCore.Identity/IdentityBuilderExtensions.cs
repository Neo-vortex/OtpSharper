using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace OtpSharper.AspNetCore.Identity;

/// <summary>
/// Registration helpers for wiring <see cref="OtpSharperTotpTokenProvider{TUser}"/>
/// into ASP.NET Core Identity.
/// </summary>
public static class IdentityBuilderExtensions
{
    /// <summary>
    /// Registers <see cref="OtpSharperTotpTokenProvider{TUser}"/> as an Identity two-factor
    /// token provider.
    /// </summary>
    /// <param name="builder">The Identity builder (from <c>AddIdentity</c>/<c>AddIdentityCore</c>).</param>
    /// <param name="configure">Optional configuration for algorithm, digits, and replay tracking.</param>
    /// <param name="tokenProviderName">
    /// Provider name used when calling <c>GenerateTwoFactorTokenAsync</c> /
    /// <c>VerifyTwoFactorTokenAsync</c>. Default: <c>"OtpSharper"</c>. Use Identity's own
    /// <c>"Authenticator"</c> name instead if you want this to be a transparent swap for the
    /// built-in provider without changing calling code.
    /// </param>
    /// <example>
    /// <code>
    /// services.AddIdentity&lt;ApplicationUser, IdentityRole&gt;()
    ///     .AddEntityFrameworkStores&lt;AppDbContext&gt;()
    ///     .AddOtpSharperTwoFactorTokenProvider&lt;ApplicationUser&gt;();
    /// </code>
    /// </example>
    public static IdentityBuilder AddOtpSharperTwoFactorTokenProvider<TUser>(
        this IdentityBuilder builder,
        Action<OtpSharperTotpOptions>? configure = null,
        string tokenProviderName = "OtpSharper")
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(tokenProviderName);

        var options = new OtpSharperTotpOptions();
        configure?.Invoke(options);

        builder.Services.AddSingleton(options);
        return builder.AddTokenProvider<OtpSharperTotpTokenProvider<TUser>>(tokenProviderName);
    }
}
