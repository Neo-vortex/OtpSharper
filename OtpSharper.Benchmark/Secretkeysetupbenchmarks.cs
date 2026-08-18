using BenchmarkDotNet.Attributes;
using OtpNet;
using OtpSharper.Core;
using OtpSharper.Totp;

namespace OtpSharper.Benchmark;

/// <summary>
/// Benchmarks the cost of setting up OTP objects from scratch.
/// This matters for short-lived per-request scenarios (e.g., stateless APIs).
/// </summary>
[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByCategory)]
public class SecretKeySetupBenchmarks
{
    private static readonly byte[] SecretBytes = "12345678901234567890"u8.ToArray();
    private static readonly string SecretBase32 =
        OtpSharper.Core.Base32.Encode(SecretBytes, padOutput: false);

    // ── Create generator + generate code (full per-request flow) ─────────────

    /// <summary>
    /// Full cold-path: construct Totp, compute code — typical for stateless APIs
    /// that don't cache the OTP generator instance.
    /// </summary>
    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("Setup_And_Generate")]
    public string TheirSetupAndGenerate()
    {
        var totp = new OtpNet.Totp(SecretBytes);
        return totp.ComputeTotp();
    }

    [Benchmark(Description = "OtpSharper")]
    [BenchmarkCategory("Setup_And_Generate")]
    public string OurSetupAndGenerate()
    {
        using var secret = new OtpSecret(SecretBytes);
        var totp = new TotpGenerator(secret);
        return totp.Generate().Code;
    }

    // ── Create from Base32 + generate (realistic enrollment path) ─────────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("Setup_FromBase32_Generate")]
    public string TheirFromBase32Generate()
    {
        var keyBytes = Base32Encoding.ToBytes(SecretBase32);
        var totp = new OtpNet.Totp(keyBytes);
        return totp.ComputeTotp();
    }

    [Benchmark(Description = "OtpSharper")]
    [BenchmarkCategory("Setup_FromBase32_Generate")]
    public string OurFromBase32Generate()
    {
        using var secret = OtpSecret.FromBase32(SecretBase32);
        var totp = new TotpGenerator(secret);
        return totp.Generate().Code;
    }

    // ── Create generator only (no generation, tests object allocation) ────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("Setup_ObjectCreation")]
    public OtpNet.Totp TheirCreateOnly() => new OtpNet.Totp(SecretBytes);

    [Benchmark(Description = "OtpSharper")]
    [BenchmarkCategory("Setup_ObjectCreation")]
    public TotpGenerator OurCreateOnly()
    {
        var secret = new OtpSecret(SecretBytes);
        return new TotpGenerator(secret);
    }
}
