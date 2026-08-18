using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OtpSharper.Totp;
using Xunit;

namespace OtpSharper.AspNetCore.Identity.Tests;

public class TestUser
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
}

public class IdentityBuilderExtensionsTests
{
    private static IdentityBuilder NewIdentityBuilder(IServiceCollection? services = null)
        => (services ?? new ServiceCollection()).AddIdentityCore<TestUser>();

    [Fact]
    public void AddOtpSharperTwoFactorTokenProvider_RegistersOptionsSingleton()
    {
        var services = new ServiceCollection();
        NewIdentityBuilder(services).AddOtpSharperTwoFactorTokenProvider<TestUser>();

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<OtpSharperTotpOptions>();

        options.Should().NotBeNull();
        options.TotpOptions.Should().BeEquivalentTo(TotpOptions.GoogleAuthenticator);
        options.ReplayTracker.Should().BeNull();
    }

    [Fact]
    public void AddOtpSharperTwoFactorTokenProvider_AppliesConfigureDelegate()
    {
        var services = new ServiceCollection();
        NewIdentityBuilder(services).AddOtpSharperTwoFactorTokenProvider<TestUser>(
            options => options.TotpOptions = TotpOptions.HighSecurity);

        var options = services.BuildServiceProvider().GetRequiredService<OtpSharperTotpOptions>();

        options.TotpOptions.Should().BeEquivalentTo(TotpOptions.HighSecurity);
    }

    [Fact]
    public void AddOtpSharperTwoFactorTokenProvider_RegistersUnderDefaultProviderName()
    {
        var services = new ServiceCollection();
        NewIdentityBuilder(services).AddOtpSharperTwoFactorTokenProvider<TestUser>();

        var identityOptions = services.BuildServiceProvider()
            .GetRequiredService<IOptions<IdentityOptions>>().Value;

        identityOptions.Tokens.ProviderMap.Should().ContainKey("OtpSharper");
        identityOptions.Tokens.ProviderMap["OtpSharper"].ProviderType
            .Should().Be(typeof(OtpSharperTotpTokenProvider<TestUser>));
    }

    [Fact]
    public void AddOtpSharperTwoFactorTokenProvider_RegistersUnderCustomProviderName()
    {
        var services = new ServiceCollection();
        NewIdentityBuilder(services).AddOtpSharperTwoFactorTokenProvider<TestUser>(tokenProviderName: "Authenticator");

        var identityOptions = services.BuildServiceProvider()
            .GetRequiredService<IOptions<IdentityOptions>>().Value;

        identityOptions.Tokens.ProviderMap.Should().ContainKey("Authenticator");
        identityOptions.Tokens.ProviderMap.Should().NotContainKey("OtpSharper");
    }

    [Fact]
    public void AddOtpSharperTwoFactorTokenProvider_RegistersProviderResolvableFromDi()
    {
        var services = new ServiceCollection();
        NewIdentityBuilder(services).AddOtpSharperTwoFactorTokenProvider<TestUser>();

        var provider = services.BuildServiceProvider().GetService<OtpSharperTotpTokenProvider<TestUser>>();

        provider.Should().NotBeNull();
    }

    [Fact]
    public void AddOtpSharperTwoFactorTokenProvider_Throws_ForNullBuilder()
    {
        IdentityBuilder builder = null!;

        Action act = () => builder.AddOtpSharperTwoFactorTokenProvider<TestUser>();

        act.Should().Throw<ArgumentNullException>();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void AddOtpSharperTwoFactorTokenProvider_Throws_ForNullOrEmptyProviderName(string? providerName)
    {
        var builder = NewIdentityBuilder();

        Action act = () => builder.AddOtpSharperTwoFactorTokenProvider<TestUser>(tokenProviderName: providerName!);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void AddOtpSharperTwoFactorTokenProvider_ReturnsSameBuilder_ForChaining()
    {
        var services = new ServiceCollection();
        var builder = NewIdentityBuilder(services);

        var result = builder.AddOtpSharperTwoFactorTokenProvider<TestUser>();

        result.Should().BeSameAs(builder);
    }
}
