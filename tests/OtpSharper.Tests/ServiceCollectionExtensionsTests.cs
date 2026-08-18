using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using OtpSharper.Abstractions;
using OtpSharper.Algorithms;
using OtpSharper.Core;
using OtpSharper.Extensions;
using OtpSharper.OutOfBand;
using OtpSharper.Totp;
using Xunit;

namespace OtpSharper.Tests;

public class ServiceCollectionExtensionsTests
{
    private static string NewSecret() => OtpSecret.Generate().ToBase32();

    [Fact]
    public void AddTotp_WithOptions_RegistersConfiguredGenerator()
    {
        var services = new ServiceCollection();
        services.AddTotp(NewSecret(), new TotpOptions { Digits = 8, Algorithm = OtpAlgorithm.HmacSha256 });

        var provider = services.BuildServiceProvider();
        var generator = provider.GetRequiredService<TotpGenerator>();

        generator.Options.Digits.Should().Be(8);
        generator.Options.Algorithm.Should().Be(OtpAlgorithm.HmacSha256);
    }

    [Fact]
    public void AddTotp_WithoutOptions_UsesDefault()
    {
        var services = new ServiceCollection();
        services.AddTotp(NewSecret());

        var generator = services.BuildServiceProvider().GetRequiredService<TotpGenerator>();

        generator.Options.Digits.Should().Be(TotpOptions.DefaultDigits);
        generator.Options.Algorithm.Should().Be(TotpOptions.DefaultAlgorithm);
    }

    [Fact]
    public void AddTotp_WithBuilderAction_RegistersConfiguredGenerator()
    {
        var services = new ServiceCollection();
        services.AddTotp(NewSecret(), b => b.WithDigits(8).WithAlgorithm(OtpAlgorithm.HmacSha512));

        var generator = services.BuildServiceProvider().GetRequiredService<TotpGenerator>();

        generator.Options.Digits.Should().Be(8);
        generator.Options.Algorithm.Should().Be(OtpAlgorithm.HmacSha512);
    }

    [Fact]
    public void AddTotp_WithBuilderAction_PropagatesValidationFailure()
    {
        var services = new ServiceCollection();

        Action act = () => services.AddTotp(NewSecret(), b => b.WithStepSeconds(-1));

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void AddOtpManager_RegistersManagerFromUri()
    {
        var manager = OtpSharper.OtpManager.Create("alice@example.com", "Example");
        string uri = manager.GetOtpAuthUri();

        var services = new ServiceCollection();
        services.AddOtpManager(uri);

        var resolved = services.BuildServiceProvider().GetRequiredService<OtpSharper.OtpManager>();

        resolved.Validate(manager.Generate().Code).Should().BeTrue();
    }

    [Fact]
    public void AddTotpValidationService_UsesProvidedOptions()
    {
        var services = new ServiceCollection();
        services.AddTotpValidationService(new TotpOptions { Digits = 8 });

        var service = services.BuildServiceProvider().GetRequiredService<TotpValidationService>();

        service.Options.Digits.Should().Be(8);
    }

    [Fact]
    public void AddOtpBackoffPolicy_UsesProvidedOptions()
    {
        var services = new ServiceCollection();
        services.AddOtpBackoffPolicy(new OtpBackoffOptions { MaxFailedAttempts = 2 });

        var policy = services.BuildServiceProvider().GetRequiredService<OtpBackoffPolicy>();

        policy.RecordFailure("user1");
        var result = policy.RecordFailure("user1");

        result.IsLockedOut.Should().BeTrue();
    }

    [Fact]
    public void AddOtpBackoffPolicy_WithoutOptions_UsesDefaults()
    {
        var services = new ServiceCollection();
        services.AddOtpBackoffPolicy();

        var policy = services.BuildServiceProvider().GetRequiredService<OtpBackoffPolicy>();

        policy.CheckAllowed("user1").RemainingAttempts.Should().Be(5);
    }

    [Fact]
    public async Task AddOtpUsedCodeTracker_RegistersConcreteTypeAndInterfaceAsSameInstance()
    {
        var services = new ServiceCollection();
        services.AddOtpUsedCodeTracker();

        var provider = services.BuildServiceProvider();
        var concrete = provider.GetRequiredService<UsedCodeTracker>();
        var asInterface = provider.GetRequiredService<IUsedCodeStore>();

        concrete.TryMarkUsed("user1", 1);
        (await asInterface.IsUsedAsync("user1", 1)).Should().BeTrue("both registrations should resolve to the same singleton");
    }

    [Fact]
    public void AddOobCodeGenerator_RegistersInMemoryStore_WhenNoneRegistered()
    {
        var services = new ServiceCollection();
        services.AddOobCodeGenerator();

        var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IOobCodeStore>().Should().BeOfType<InMemoryOobCodeStore>();
        provider.GetRequiredService<OobCodeGenerator>().Should().NotBeNull();
    }

    [Fact]
    public void AddOobCodeGenerator_DoesNotOverrideExistingStore()
    {
        var services = new ServiceCollection();
        var customStore = new InMemoryOobCodeStore();
        services.AddSingleton<IOobCodeStore>(customStore);

        services.AddOobCodeGenerator();

        var resolved = services.BuildServiceProvider().GetRequiredService<IOobCodeStore>();
        resolved.Should().BeSameAs(customStore);
    }
}
