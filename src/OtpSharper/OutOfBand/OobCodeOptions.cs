namespace OtpSharper.OutOfBand;

/// <summary>
/// Configuration for <see cref="OobCodeGenerator"/>.
/// </summary>
public sealed class OobCodeOptions
{
    /// <summary>Number of digits in the generated code. Default: 6.</summary>
    public int Digits { get; set; } = 6;

    /// <summary>How long a code remains valid after generation. Default: 5 minutes.</summary>
    public TimeSpan Ttl { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Maximum number of failed validation attempts before the code is invalidated
    /// and must be re-requested. Default: 5.
    /// </summary>
    public int MaxAttempts { get; set; } = 5;

    /// <summary>Validates this configuration.</summary>
    /// <exception cref="ArgumentOutOfRangeException">If any value is out of range.</exception>
    internal void Validate()
    {
        if (Digits is < 4 or > 10)
            throw new ArgumentOutOfRangeException(nameof(Digits), Digits, "Digits must be between 4 and 10.");
        if (Ttl <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(Ttl), Ttl, "Ttl must be positive.");
        if (MaxAttempts < 1)
            throw new ArgumentOutOfRangeException(nameof(MaxAttempts), MaxAttempts, "MaxAttempts must be at least 1.");
    }
}
