using QRCoder;

namespace OtpSharper.Uri;

/// <summary>
/// Local QR code generation for <see cref="OtpUri"/>, with no network dependency.
/// </summary>
/// <remarks>
/// Replaces <see cref="OtpUri.ToQrCodeImageUrl"/>, which relied on the Google Charts
/// Image API — that API was shut down in 2019 and no longer returns images. These
/// methods render the QR code entirely locally via <see href="https://github.com/codebude/QRCoder">QRCoder</see>,
/// which also keeps the (secret-containing) <c>otpauth://</c> URI from ever being sent
/// to a third party just to render a QR code.
/// </remarks>
public static class OtpQrCode
{
    /// <summary>
    /// Renders this URI as a QR code and returns raw PNG bytes.
    /// </summary>
    /// <param name="uri">The OTP URI to encode.</param>
    /// <param name="pixelsPerModule">Size of each QR module in pixels. Default: 10.</param>
    /// <param name="eccLevel">Error-correction level. Default: <c>Q</c> (25% recovery), a common choice for authenticator QR codes.</param>
    public static byte[] ToQrCodePng(
        this OtpUri uri,
        int pixelsPerModule = 10,
        QRCodeGenerator.ECCLevel eccLevel = QRCodeGenerator.ECCLevel.Q)
    {
        ArgumentNullException.ThrowIfNull(uri);
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(uri.ToUriString(), eccLevel);
        var png = new PngByteQRCode(data);
        return png.GetGraphic(pixelsPerModule);
    }

    /// <summary>
    /// Renders this URI as a QR code and returns SVG markup.
    /// </summary>
    /// <param name="uri">The OTP URI to encode.</param>
    /// <param name="pixelsPerModule">Size of each QR module in pixels. Default: 10.</param>
    /// <param name="eccLevel">Error-correction level. Default: <c>Q</c>.</param>
    public static string ToQrCodeSvg(
        this OtpUri uri,
        int pixelsPerModule = 10,
        QRCodeGenerator.ECCLevel eccLevel = QRCodeGenerator.ECCLevel.Q)
    {
        ArgumentNullException.ThrowIfNull(uri);
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(uri.ToUriString(), eccLevel);
        var svg = new SvgQRCode(data);
        return svg.GetGraphic(pixelsPerModule);
    }

    /// <summary>
    /// Renders this URI as a QR code and returns it as a <c>data:image/png;base64,...</c> URI —
    /// convenient for dropping straight into an <c>&lt;img src="..."&gt;</c> tag server-side
    /// with no separate image endpoint required.
    /// </summary>
    /// <param name="uri">The OTP URI to encode.</param>
    /// <param name="pixelsPerModule">Size of each QR module in pixels. Default: 10.</param>
    /// <param name="eccLevel">Error-correction level. Default: <c>Q</c>.</param>
    public static string ToQrCodeDataUri(
        this OtpUri uri,
        int pixelsPerModule = 10,
        QRCodeGenerator.ECCLevel eccLevel = QRCodeGenerator.ECCLevel.Q)
    {
        byte[] png = uri.ToQrCodePng(pixelsPerModule, eccLevel);
        return $"data:image/png;base64,{Convert.ToBase64String(png)}";
    }
}
