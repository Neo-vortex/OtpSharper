using FluentAssertions;
using OtpSharper.Core;
using OtpSharper.Uri;
using Xunit;

namespace OtpSharper.Tests;

public class OtpQrCodeTests
{
    private static OtpUri BuildUri()
    {
        using var secret = OtpSecret.FromBase32("JBSWY3DPEHPK3PXP");
        return OtpUri.ForTotp("alice@example.com", secret, issuer: "MyApp");
    }

    [Fact]
    public void ToQrCodePng_ProducesValidPngSignature()
    {
        byte[] png = BuildUri().ToQrCodePng();

        // Every PNG file starts with this fixed 8-byte signature (RFC 2083 §3.1).
        byte[] pngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

        png.Should().NotBeEmpty();
        png.Take(8).Should().Equal(pngSignature);
    }

    [Fact]
    public void ToQrCodePng_LargerPixelsPerModule_ProducesLargerImage()
    {
        OtpUri uri = BuildUri();

        byte[] small = uri.ToQrCodePng(pixelsPerModule: 2);
        byte[] large = uri.ToQrCodePng(pixelsPerModule: 20);

        large.Length.Should().BeGreaterThan(small.Length);
    }

    [Fact]
    public void ToQrCodeSvg_ProducesSvgMarkup()
    {
        string svg = BuildUri().ToQrCodeSvg();

        svg.Should().Contain("<svg");
        svg.Should().Contain("</svg>");
    }

    [Fact]
    public void ToQrCodeDataUri_HasCorrectPrefixAndDecodesToPng()
    {
        string dataUri = BuildUri().ToQrCodeDataUri();

        dataUri.Should().StartWith("data:image/png;base64,");

        string base64 = dataUri["data:image/png;base64,".Length..];
        byte[] decoded = Convert.FromBase64String(base64);
        decoded.Take(8).Should().Equal((byte)0x89, (byte)0x50, (byte)0x4E, (byte)0x47, (byte)0x0D, (byte)0x0A, (byte)0x1A, (byte)0x0A);
    }

    [Fact]
    public void ToQrCodePng_ThrowsForNullUri()
    {
        OtpUri? uri = null;
        Action act = () => uri!.ToQrCodePng();
        act.Should().Throw<ArgumentNullException>();
    }

#pragma warning disable CS0618 // testing the obsolete member intentionally
    [Fact]
    public void ToQrCodeImageUrl_StillBuildsAUrl_ButIsObsolete()
    {
        // The Google Charts endpoint this builds a URL for no longer serves images (shut down
        // in 2019) — this test only confirms the deprecated method still constructs the string
        // it always did, not that the URL is actually usable. See ToQrCodePng/Svg/DataUri instead.
        string url = BuildUri().ToQrCodeImageUrl();
        url.Should().StartWith("https://chart.googleapis.com/chart?");
    }
#pragma warning restore CS0618
}
