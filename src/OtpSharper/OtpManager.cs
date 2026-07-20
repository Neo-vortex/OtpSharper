using OtpSharper.Hotp;
using OtpSharper.Core;
using OtpSharper.Totp;
using OtpSharper.Uri;

namespace OtpSharper;

/// <summary>
/// High-level facade that combines TOTP generation, validation, and URI management.
/// This is the recommended entry point for most applications.
/// </summary>
/// <example>
/// <code>
/// // Enrol a new user
/// var manager = OtpManager.Create("user@example.com", issuer: "MyApp");
/// string qrUri = manager.GetQrCodeUrl();
/// string setupKey = manager.GetSetupKey();
///
/// // Later: validate input
/// bool valid = manager.Validate(userInput);
/// </code>
/// </example>
public sealed class OtpManager
{
    private readonly TotpGenerator _generator;
    private readonly OtpUri        _uri;

    // ── Construction ──────────────────────────────────────────────────────────

    private OtpManager(OtpSecret secret, string label, string? issuer, TotpOptions options)
    {
        _generator = new TotpGenerator(secret, options);
        _uri       = OtpUri.ForTotp(label, secret, options, issuer);
    }

    /// <summary>
    /// Creates an <see cref="OtpManager"/> with a newly generated secret.
    /// </summary>
    /// <param name="label">Account label (e.g., user@example.com).</param>
    /// <param name="issuer">Application/service name.</param>
    /// <param name="options">TOTP options. Null = RFC 6238 defaults.</param>
    public static OtpManager Create(string label, string? issuer = null, TotpOptions? options = null)
    {
        options ??= TotpOptions.Default;
        var secret = OtpSecret.Generate(SecretByteLengthFor(options));
        return new OtpManager(secret, label, issuer, options);
    }

    /// <summary>
    /// Creates an <see cref="OtpManager"/> from an existing Base32-encoded secret.
    /// </summary>
    public static OtpManager FromBase32(string base32Secret, string label, string? issuer = null, TotpOptions? options = null)
    {
        var secret = OtpSecret.FromBase32(base32Secret);
        return new OtpManager(secret, label, issuer, options ?? TotpOptions.Default);
    }

    /// <summary>
    /// Creates an <see cref="OtpManager"/> from an existing <c>otpauth://</c> URI.
    /// </summary>
    public static OtpManager FromUri(string otpauthUri)
    {
        var uri = OtpUri.Parse(otpauthUri);
        if (uri.Type != OtpUriType.Totp)
            throw new InvalidOperationException("OtpManager only supports TOTP. Use HotpGenerator for HOTP.");

        var secret = OtpSecret.FromBase32(uri.Secret);
        var options = new TotpOptions
        {
            Algorithm   = uri.Algorithm,
            Digits      = uri.Digits,
            StepSeconds = uri.Period,
        };
        return new OtpManager(secret, uri.Label, uri.Issuer, options);
    }

    // ── Generation ────────────────────────────────────────────────────────────

    /// <summary>Generates the current TOTP code.</summary>
    public OtpCode Generate() => _generator.Generate();

    /// <summary>Generates the TOTP code at a specific timestamp.</summary>
    public OtpCode GenerateAt(DateTimeOffset timestamp) => _generator.GenerateAt(timestamp);

    // ── Validation ────────────────────────────────────────────────────────────

    /// <summary>
    /// Validates a user-supplied code. Returns <c>true</c> if valid.
    /// </summary>
    public bool Validate(string userCode)
        => _generator.Validate(userCode).IsValid;

    /// <summary>
    /// Validates a user-supplied code, returning rich result metadata.
    /// </summary>
    public OtpValidationResult ValidateWithDetails(string userCode)
        => _generator.Validate(userCode);

    // ── Setup / provisioning ──────────────────────────────────────────────────

    /// <summary>Returns the secret as a Base32 string for display to the user.</summary>
    public string GetSetupKey() => _uri.Secret;

    /// <summary>Returns the <c>otpauth://</c> URI for QR code generation.</summary>
    public string GetOtpAuthUri() => _uri.ToUriString();

    /// <summary>Returns a Google Charts QR code URL for displaying a setup QR code.</summary>
    /// <param name="size">Image size in pixels.</param>
    [Obsolete("The Google Charts Image API was shut down in 2019; this URL no longer renders an image. " +
        "Use GetQrCodePng, GetQrCodeSvg, or GetQrCodeDataUri instead.")]
    public string GetQrCodeUrl(int size = 300) => _uri.ToQrCodeImageUrl(size);

    /// <summary>Renders a setup QR code locally and returns raw PNG bytes.</summary>
    /// <param name="pixelsPerModule">Size of each QR module in pixels. Default: 10.</param>
    public byte[] GetQrCodePng(int pixelsPerModule = 10) => _uri.ToQrCodePng(pixelsPerModule);

    /// <summary>Renders a setup QR code locally and returns SVG markup.</summary>
    /// <param name="pixelsPerModule">Size of each QR module in pixels. Default: 10.</param>
    public string GetQrCodeSvg(int pixelsPerModule = 10) => _uri.ToQrCodeSvg(pixelsPerModule);

    /// <summary>Renders a setup QR code locally and returns a <c>data:image/png;base64,...</c> URI.</summary>
    /// <param name="pixelsPerModule">Size of each QR module in pixels. Default: 10.</param>
    public string GetQrCodeDataUri(int pixelsPerModule = 10) => _uri.ToQrCodeDataUri(pixelsPerModule);

    // ── Time helpers ──────────────────────────────────────────────────────────

    /// <summary>Remaining seconds in the current time step.</summary>
    public int RemainingSeconds() => _generator.RemainingSeconds();

    /// <summary>When the current code expires.</summary>
    public DateTimeOffset CurrentExpiry() => _generator.CurrentExpiry();

    /// <summary>The active configuration.</summary>
    public TotpOptions Options => _generator.Options;

    // ── Window ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns all codes in the current validation window (useful for debugging).
    /// </summary>
    public IReadOnlyList<(int Offset, OtpCode Code)> GetCurrentWindow()
        => _generator.GenerateWindow();

    // ── Private helpers ───────────────────────────────────────────────────────

    private static int SecretByteLengthFor(TotpOptions options) => options.Algorithm switch
    {
        Algorithms.OtpAlgorithm.HmacSha1     => 20,
        Algorithms.OtpAlgorithm.HmacSha256   => 32,
        Algorithms.OtpAlgorithm.HmacSha384   => 48,
        Algorithms.OtpAlgorithm.HmacSha512   => 64,
        Algorithms.OtpAlgorithm.HmacSha3_256 => 32,
        Algorithms.OtpAlgorithm.HmacSha3_512 => 64,
        _                                     => 20,
    };
}
