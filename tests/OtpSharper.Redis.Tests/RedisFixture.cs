using StackExchange.Redis;
using Xunit;

namespace OtpSharper.Redis.Tests;

/// <summary>
/// Connects once per test run to a real Redis instance for the integration tests in this
/// project, so <see cref="RedisOobCodeStore"/>, <see cref="RedisHotpCounterStore"/>, and
/// <see cref="RedisUsedCodeStore"/> are exercised against the real protocol rather than a mock —
/// StackExchange.Redis's <see cref="IDatabase"/> surface is large enough that a hand-rolled mock
/// would mostly be re-asserting the mock's own behaviour, not this project's.
/// </summary>
/// <remarks>
/// Address defaults to <c>localhost:6379</c>; override with the <c>OTPSHARPER_TEST_REDIS</c>
/// environment variable. Start one locally with e.g. <c>docker run --rm -p 6379:6379 redis</c>.
/// If no Redis is reachable, <see cref="IsAvailable"/> is <c>false</c> and every test in this
/// project no-ops rather than failing — these are integration tests for local/CI environments
/// that opt in by running a Redis instance, not a hard requirement for the rest of the solution.
/// </remarks>
public sealed class RedisFixture : IAsyncLifetime
{
    /// <summary>The shared connection, or null if Redis wasn't reachable during setup.</summary>
    public IConnectionMultiplexer? Connection { get; private set; }

    /// <summary>Whether a Redis connection was successfully established.</summary>
    public bool IsAvailable => Connection is { IsConnected: true };

    /// <inheritdoc />
    public async Task InitializeAsync()
    {
        try
        {
            var options = ConfigurationOptions.Parse(
                Environment.GetEnvironmentVariable("OTPSHARPER_TEST_REDIS") ?? "localhost:6379");
            options.ConnectTimeout = 500;
            options.AbortOnConnectFail = false;

            var connection = await ConnectionMultiplexer.ConnectAsync(options).ConfigureAwait(false);
            Connection = connection.IsConnected ? connection : null;
            if (Connection is null)
                connection.Dispose();
        }
        catch
        {
            Connection = null; // no Redis reachable — tests will no-op, see class remarks
        }
    }

    /// <inheritdoc />
    public Task DisposeAsync()
    {
        Connection?.Dispose();
        return Task.CompletedTask;
    }
}

/// <summary>Shares one <see cref="RedisFixture"/> across every test class in this project.</summary>
[CollectionDefinition("Redis")]
public sealed class RedisCollection : ICollectionFixture<RedisFixture>;
