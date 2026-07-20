using Microsoft.Extensions.DependencyInjection;
using OtpSharper.Abstractions;
using OtpSharper.Hotp;
using OtpSharper.OutOfBand;
using StackExchange.Redis;

namespace OtpSharper.Redis;

/// <summary>
/// Extension methods for registering this package's Redis-backed stores with
/// <see cref="IServiceCollection"/>. Every method here requires an
/// <see cref="IConnectionMultiplexer"/> to already be registered — typically via
/// <c>services.AddSingleton&lt;IConnectionMultiplexer&gt;(_ =&gt; ConnectionMultiplexer.Connect(connectionString))</c>,
/// the standard StackExchange.Redis pattern. Reusing your app's existing multiplexer (rather
/// than opening a new connection per store) is intentional: multiplexers are meant to be
/// shared and are expensive to create.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="RedisOobCodeStore"/> as the <see cref="IOobCodeStore"/> implementation.
    /// </summary>
    /// <remarks>
    /// Call this before <c>AddOobCodeGenerator</c> from the core package if you use both, so the
    /// generator picks up this registration instead of the in-memory default.
    /// </remarks>
    public static IServiceCollection AddRedisOobCodeStore(
        this IServiceCollection services,
        string keyPrefix = "otpsharper:oob:")
    {
        services.AddSingleton<IOobCodeStore>(sp =>
            new RedisOobCodeStore(sp.GetRequiredService<IConnectionMultiplexer>(), keyPrefix));
        return services;
    }

    /// <summary>
    /// Registers <see cref="RedisHotpCounterStore"/> as the <see cref="IHotpCounterStore"/>
    /// implementation, for HOTP deployments spanning more than one instance.
    /// </summary>
    public static IServiceCollection AddRedisHotpCounterStore(
        this IServiceCollection services,
        string keyPrefix = "otpsharper:hotp:")
    {
        services.AddSingleton<IHotpCounterStore>(sp =>
            new RedisHotpCounterStore(sp.GetRequiredService<IConnectionMultiplexer>(), keyPrefix));
        return services;
    }

    /// <summary>
    /// Registers <see cref="RedisUsedCodeStore"/> as the <see cref="IUsedCodeStore"/>
    /// implementation, for replay protection spanning more than one instance.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="maxAge">
    /// How long a "used" marker is kept before Redis expires it. Should be at least as long as
    /// (windowSteps * stepSeconds * 2). Default: 90 seconds.
    /// </param>
    /// <param name="keyPrefix">Prefix applied to every Redis key this store creates.</param>
    public static IServiceCollection AddRedisUsedCodeStore(
        this IServiceCollection services,
        TimeSpan? maxAge = null,
        string keyPrefix = "otpsharper:used:")
    {
        services.AddSingleton<IUsedCodeStore>(sp =>
            new RedisUsedCodeStore(sp.GetRequiredService<IConnectionMultiplexer>(), maxAge, keyPrefix));
        return services;
    }
}
