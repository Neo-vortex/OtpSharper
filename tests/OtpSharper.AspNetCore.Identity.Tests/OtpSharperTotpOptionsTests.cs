using FluentAssertions;
using OtpSharper.Abstractions;
using OtpSharper.Totp;
using Xunit;

namespace OtpSharper.AspNetCore.Identity.Tests;

public class OtpSharperTotpOptionsTests
{
    [Fact]
    public void Defaults_UseGoogleAuthenticatorPresetAndNoReplayTracking()
    {
        var options = new OtpSharperTotpOptions();

        options.TotpOptions.Should().BeEquivalentTo(TotpOptions.GoogleAuthenticator);
        options.ReplayTracker.Should().BeNull();
    }

    [Fact]
    public void TotpOptions_IsSettable()
    {
        var options = new OtpSharperTotpOptions { TotpOptions = TotpOptions.MaxSecurity };

        options.TotpOptions.Should().BeEquivalentTo(TotpOptions.MaxSecurity);
    }

    [Fact]
    public void ReplayTracker_IsSettable()
    {
        var tracker = new UsedCodeTracker();

        var options = new OtpSharperTotpOptions { ReplayTracker = tracker };

        options.ReplayTracker.Should().BeSameAs(tracker);
    }
}
