using System.Text;
using System.Web;
using OtpSharper.Algorithms;
using OtpSharper.Core;
using OtpSharper.Hotp;
using OtpSharper.Totp;

namespace OtpSharper.Uri;

/// <summary>
/// The OTP type encoded in an otpauth:// URI.
/// </summary>
public enum OtpUriType
{
    /// <summary>Time-based OTP (RFC 6238).</summary>
    Totp,
    /// <summary>HMAC-based OTP (RFC 4226).</summary>
    Hotp,
}

/// <summary>
/// Builds and parses <c>otpauth://</c> URIs as defined by the Google Authenticator Key URI Format.
/// </summary>
/// <remarks>
/// URI format: <c>otpauth://TYPE/LABEL?PARAMETERS</c>
/// <br/>
/// See: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
/// </remarks>
public sealed class OtpUri
{
    // ── Reserved parameter names (spec-defined) ───────────────────────────────

    private static readonly HashSet<string> ReservedKeys =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "secret", "issuer", "algorithm", "digits", "period", "counter",
        };

    // ── Properties ────────────────────────────────────────────────────────────

    /// <summary>OTP type: totp or hotp.</summary>
    public OtpUriType Type { get; init; } = OtpUriType.Totp;

    /// <summary>Account label (e.g., user@example.com).</summary>
    public string Label { get; init; } = string.Empty;

    /// <summary>Issuer name (e.g., "MyApp"). Shown in authenticator apps.</summary>
    public string? Issuer { get; init; }

    /// <summary>Base32-encoded secret (no padding).</summary>
    public string Secret { get; init; } = string.Empty;

    /// <summary>HMAC algorithm.</summary>
    public OtpAlgorithm Algorithm { get; init; } = OtpAlgorithm.HmacSha1;

    /// <summary>Number of OTP digits.</summary>
    public int Digits { get; init; } = TotpOptions.DefaultDigits;

    /// <summary>Time step in seconds (TOTP only).</summary>
    public int Period { get; init; } = TotpOptions.DefaultStepSeconds;

    /// <summary>Initial counter value (HOTP only).</summary>
    public long Counter { get; init; } = 0;

    /// <summary>
    /// Optional custom query parameters appended after the standard parameters.
    /// Keys and values are URL-encoded automatically when the URI is built.
    /// Unknown keys encountered during parsing are preserved here.
    /// </summary>
    /// <remarks>
    /// Reserved parameter names (<c>secret</c>, <c>issuer</c>, <c>algorithm</c>,
    /// <c>digits</c>, <c>period</c>, <c>counter</c>) are not allowed as keys and
    /// will cause an <see cref="InvalidOperationException"/> when
    /// <see cref="ToUriString"/> is called.
    /// </remarks>
    /// <example>
    /// <code>
    /// var uri = OtpUri.ForTotp("alice@example.com", secret, options, issuer: "MyApp",
    ///     extraParameters: new Dictionary&lt;string, string&gt;
    ///     {
    ///         ["image"] = "https://example.com/logo.png",
    ///         ["x-app-id"] = "prod-42",
    ///     });
    ///
    /// // => otpauth://totp/...?secret=...&amp;image=https%3A...&amp;x-app-id=prod-42
    /// </code>
    /// </example>
    public IReadOnlyDictionary<string, string> ExtraParameters { get; init; }
        = new Dictionary<string, string>();

    // ── Build ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Builds the <c>otpauth://</c> URI string.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown if <see cref="ExtraParameters"/> contains a reserved key name.
    /// </exception>
    public string ToUriString()
    {
        if (string.IsNullOrEmpty(Secret))
            throw new InvalidOperationException("Secret must not be empty.");
        if (string.IsNullOrEmpty(Label))
            throw new InvalidOperationException("Label must not be empty.");

        ValidateExtraParameters();

        string type  = Type == OtpUriType.Totp ? "totp" : "hotp";
        string label = BuildLabel();
        var sb = new StringBuilder();

        sb.Append("otpauth://")
          .Append(type)
          .Append('/')
          .Append(label)
          .Append("?secret=")
          .Append(HttpUtility.UrlEncode(Secret.ToUpperInvariant().Replace("=", "")));

        if (!string.IsNullOrEmpty(Issuer))
            sb.Append("&issuer=").Append(HttpUtility.UrlEncode(Issuer));

        if (Algorithm != OtpAlgorithm.HmacSha1)
            sb.Append("&algorithm=").Append(HmacProvider.ToUriString(Algorithm));

        if (Digits != 6)
            sb.Append("&digits=").Append(Digits);

        if (Type == OtpUriType.Totp && Period != TotpOptions.DefaultStepSeconds)
            sb.Append("&period=").Append(Period);

        if (Type == OtpUriType.Hotp)
            sb.Append("&counter=").Append(Counter);

        foreach (var (key, value) in ExtraParameters)
        {
            sb.Append('&')
              .Append(HttpUtility.UrlEncode(key))
              .Append('=')
              .Append(HttpUtility.UrlEncode(value));
        }

        return sb.ToString();
    }

    // ── Parse ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Parses an <c>otpauth://</c> URI string into an <see cref="OtpUri"/>.
    /// Any query parameters not defined by the spec are captured in
    /// <see cref="ExtraParameters"/>.
    /// </summary>
    /// <exception cref="FormatException">Malformed URI.</exception>
    public static OtpUri Parse(string uri)
    {
        if (!TryParse(uri, out var result, out string error))
            throw new FormatException($"Invalid otpauth URI: {error}");
        return result!;
    }

    /// <summary>
    /// Attempts to parse an <c>otpauth://</c> URI string.
    /// Any query parameters not defined by the spec are captured in
    /// <see cref="ExtraParameters"/>.
    /// </summary>
    public static bool TryParse(string uri, out OtpUri? result, out string error)
    {
        result = null;
        error  = string.Empty;

        if (!System.Uri.TryCreate(uri, UriKind.Absolute, out var parsed))
        {
            error = "Not a valid URI.";
            return false;
        }

        if (!string.Equals(parsed.Scheme, "otpauth", StringComparison.OrdinalIgnoreCase))
        {
            error = "Scheme must be 'otpauth'.";
            return false;
        }

        string typeStr = parsed.Host.ToLowerInvariant();
        if (typeStr is not ("totp" or "hotp"))
        {
            error = $"Unknown OTP type '{typeStr}'. Expected 'totp' or 'hotp'.";
            return false;
        }

        OtpUriType type = typeStr == "hotp" ? OtpUriType.Hotp : OtpUriType.Totp;

        // Label: after leading slash, issuer:account or just account
        string rawLabel = HttpUtility.UrlDecode(parsed.AbsolutePath.TrimStart('/'));
        string label, issuerFromLabel;
        int colon = rawLabel.IndexOf(':');
        if (colon >= 0)
        {
            issuerFromLabel = rawLabel[..colon].Trim();
            label           = rawLabel[(colon + 1)..].Trim();
        }
        else
        {
            issuerFromLabel = string.Empty;
            label           = rawLabel;
        }

        // Query parameters
        var query = HttpUtility.ParseQueryString(parsed.Query);
        string? secret     = query["secret"];
        string? issuerQ    = query["issuer"];
        string? algorithmQ = query["algorithm"];
        string? digitsQ    = query["digits"];
        string? periodQ    = query["period"];
        string? counterQ   = query["counter"];

        if (string.IsNullOrEmpty(secret))
        {
            error = "Missing 'secret' parameter.";
            return false;
        }

        OtpAlgorithm algorithm;
        try { algorithm = HmacProvider.FromUriString(algorithmQ); }
        catch { error = $"Unknown algorithm '{algorithmQ}'."; return false; }

        int digits = 6;
        if (digitsQ is not null && !int.TryParse(digitsQ, out digits))
        {
            error = $"Invalid 'digits' value '{digitsQ}'.";
            return false;
        }

        int period = TotpOptions.DefaultStepSeconds;
        if (periodQ is not null && !int.TryParse(periodQ, out period))
        {
            error = $"Invalid 'period' value '{periodQ}'.";
            return false;
        }

        long counter = 0;
        if (counterQ is not null && !long.TryParse(counterQ, out counter))
        {
            error = $"Invalid 'counter' value '{counterQ}'.";
            return false;
        }

        // Collect unknown keys into ExtraParameters
        var extra = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string? key in query.AllKeys)
        {
            if (key is not null && !ReservedKeys.Contains(key))
                extra[key] = query[key] ?? string.Empty;
        }

        result = new OtpUri
        {
            Type            = type,
            Label           = label,
            Issuer          = !string.IsNullOrEmpty(issuerQ) ? issuerQ : (issuerFromLabel.Length > 0 ? issuerFromLabel : null),
            Secret          = secret,
            Algorithm       = algorithm,
            Digits          = digits,
            Period          = period,
            Counter         = counter,
            ExtraParameters = extra,
        };
        return true;
    }

    // ── Factory helpers ───────────────────────────────────────────────────────

    /// <summary>
    /// Creates a TOTP URI from a <see cref="TotpOptions"/> and secret.
    /// </summary>
    /// <param name="label">Account label (e.g., user@example.com).</param>
    /// <param name="secret">The OTP secret.</param>
    /// <param name="options">TOTP options. Null = RFC 6238 defaults.</param>
    /// <param name="issuer">Application/service name.</param>
    /// <param name="extraParameters">
    /// Optional custom query parameters to include in the URI.
    /// See <see cref="ExtraParameters"/> for constraints.
    /// </param>
    public static OtpUri ForTotp(
        string label,
        OtpSecret secret,
        TotpOptions? options = null,
        string? issuer = null,
        IReadOnlyDictionary<string, string>? extraParameters = null)
    {
        options ??= TotpOptions.Default;
        return new OtpUri
        {
            Type            = OtpUriType.Totp,
            Label           = label,
            Issuer          = issuer,
            Secret          = secret.ToBase32(padOutput: false),
            Algorithm       = options.Algorithm,
            Digits          = options.Digits,
            Period          = options.StepSeconds,
            ExtraParameters = extraParameters ?? new Dictionary<string, string>(),
        };
    }

    /// <summary>
    /// Creates an HOTP URI from a <see cref="HotpOptions"/> and secret.
    /// </summary>
    /// <param name="label">Account label (e.g., user@example.com).</param>
    /// <param name="secret">The OTP secret.</param>
    /// <param name="counter">Initial counter value.</param>
    /// <param name="options">HOTP options. Null = RFC 4226 defaults.</param>
    /// <param name="issuer">Application/service name.</param>
    /// <param name="extraParameters">
    /// Optional custom query parameters to include in the URI.
    /// See <see cref="ExtraParameters"/> for constraints.
    /// </param>
    public static OtpUri ForHotp(
        string label,
        OtpSecret secret,
        long counter = 0,
        HotpOptions? options = null,
        string? issuer = null,
        IReadOnlyDictionary<string, string>? extraParameters = null)
    {
        options ??= HotpOptions.Default;
        return new OtpUri
        {
            Type            = OtpUriType.Hotp,
            Label           = label,
            Issuer          = issuer,
            Secret          = secret.ToBase32(padOutput: false),
            Algorithm       = options.Algorithm,
            Digits          = options.Digits,
            Counter         = counter,
            ExtraParameters = extraParameters ?? new Dictionary<string, string>(),
        };
    }

    // ── To typed generators ───────────────────────────────────────────────────

    /// <summary>
    /// Creates a <see cref="TotpGenerator"/> from this URI.
    /// </summary>
    /// <exception cref="InvalidOperationException">If this URI is for HOTP.</exception>
    public TotpGenerator ToTotpGenerator()
    {
        if (Type != OtpUriType.Totp)
            throw new InvalidOperationException("This URI is for HOTP, not TOTP.");

        var secret = OtpSecret.FromBase32(Secret);
        var options = new TotpOptions
        {
            Algorithm   = Algorithm,
            Digits      = Digits,
            StepSeconds = Period,
        };
        return new TotpGenerator(secret, options);
    }

    /// <summary>
    /// Creates an <see cref="HotpGenerator"/> from this URI.
    /// </summary>
    /// <exception cref="InvalidOperationException">If this URI is for TOTP.</exception>
    public HotpGenerator ToHotpGenerator()
    {
        if (Type != OtpUriType.Hotp)
            throw new InvalidOperationException("This URI is for TOTP, not HOTP.");

        var secret = OtpSecret.FromBase32(Secret);
        var options = new HotpOptions
        {
            Algorithm = Algorithm,
            Digits    = Digits,
        };
        return new HotpGenerator(secret, options);
    }

    // ── QR Code ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns a Google Charts QR code URL for this OTP URI.
    /// </summary>
    /// <param name="size">QR code image size in pixels.</param>
    /// <remarks>
    /// The Google Charts Image API this method builds a URL for was shut down in 2019
    /// and no longer serves images — this URL will not render a QR code. Use
    /// <see cref="OtpQrCode.ToQrCodePng"/>, <see cref="OtpQrCode.ToQrCodeSvg"/>, or
    /// <see cref="OtpQrCode.ToQrCodeDataUri"/> instead, which render locally and don't
    /// depend on any third-party service (or leak the secret-bearing URI to one).
    /// </remarks>
    [Obsolete("The Google Charts Image API was shut down in 2019; this URL no longer renders an image. " +
        "Use OtpQrCode.ToQrCodePng, ToQrCodeSvg, or ToQrCodeDataUri instead.")]
    public string ToQrCodeImageUrl(int size = 300)
    {
        string encoded = HttpUtility.UrlEncode(ToUriString());
        return $"https://chart.googleapis.com/chart?chs={size}x{size}&chld=M|0&cht=qr&chl={encoded}";
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private string BuildLabel()
    {
        string label = HttpUtility.UrlEncode(Label).Replace("+", "%20");
        if (!string.IsNullOrEmpty(Issuer))
            return HttpUtility.UrlEncode(Issuer).Replace("+", "%20") + ":" + label;
        return label;
    }

    /// <summary>
    /// Throws if any key in <see cref="ExtraParameters"/> clashes with a reserved
    /// spec-defined parameter name.
    /// </summary>
    private void ValidateExtraParameters()
    {
        foreach (string key in ExtraParameters.Keys)
        {
            if (ReservedKeys.Contains(key))
                throw new InvalidOperationException(
                    $"'{key}' is a reserved otpauth parameter name and cannot be used in ExtraParameters. " +
                    $"Reserved names are: {string.Join(", ", ReservedKeys)}.");
        }
    }

    /// <inheritdoc />
    public override string ToString() => ToUriString();
}
