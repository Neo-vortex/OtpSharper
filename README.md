# OtpSharper

**State-of-the-art TOTP/HOTP library for .NET 10.**

Full RFC 6238 (TOTP) and RFC 4226 (HOTP) compliance, Steam Guard support, multiple HMAC algorithms, configurable validation windows, NTP drift correction, `otpauth://` URI support, brute-force backoff protection, and a rich fluent API — built for correctness, performance, and security.

Install :
```
dotnet add package OtpSharper 
```

[![.NET](https://img.shields.io/badge/.NET-10.0-purple)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![NuGet](https://img.shields.io/badge/NuGet-1.0.0-green)](https://www.nuget.org/packages/OtpSharperer)

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [TOTP](#totp)
- [HOTP (Counter-Based)](#hotp-counter-based)
- [Steam Guard](#steam-guard)
- [otpauth:// URI](#otpauth-uri)
- [Clock Drift Correction](#clock-drift-correction)
- [Dependency Injection](#dependency-injection)
- [Security & Hardening](#security--hardening)
- [Project Structure](#project-structure)
- [Benchmarks](#benchmarks)
- [Testing](#testing)
- [RFC Compliance](#rfc-compliance)
- [License](#license)

---

## Features

| Feature | Details |
|---|---|
| **TOTP** | RFC 6238 compliant — 30s/60s/custom steps |
| **HOTP** | RFC 4226 compliant — stateful counter store |
| **Steam Guard** | Valve's custom 5-char TOTP variant |
| **Algorithms** | HMAC-SHA1, SHA256, SHA384, SHA512, SHA3-256, SHA3-512 |
| **Digits** | Configurable 1–10 digits |
| **Windows** | Asymmetric look-ahead / look-behind validation windows |
| **Epoch** | Custom T0 epoch (RFC 6238 §4) |
| **Clock sync** | NTP drift measurement + corrected time provider |
| **URI** | `otpauth://` build, parse, QR code URL |
| **DI** | `IServiceCollection` extension methods |
| **Security** | Constant-time comparison, pinned + zeroed secret memory |
| **Backoff** | Thread-safe brute-force lockout with configurable policy |
| **Secret strength** | Entropy estimation and minimum-strength enforcement |

---

## Installation

```shell
dotnet add package OtpSharper
```

**Requirements:** .NET 10.0+

---

## Quick Start

### New User Enrollment (simplest path)

```csharp
using OtpSharper;

// Generate a new secret and configure TOTP for a user
var manager = OtpManager.Create("alice@example.com", issuer: "MyApp");

// Present to the user for scanning
Console.WriteLine(manager.GetOtpAuthUri());   // otpauth://totp/...
Console.WriteLine(manager.GetSetupKey());      // JBSWY3DPEHPK3PXP (Base32)
Console.WriteLine(manager.GetQrCodeUrl());     // Google Charts QR URL

// Generate the current code
var code = manager.Generate();
Console.WriteLine($"{code.Code}  (expires in {code.RemainingSeconds}s)");

// Validate user input
bool valid = manager.Validate(userInput);
```

### Enrol from an Existing Secret

```csharp
var secret  = OtpSecret.FromBase32("JBSWY3DPEHPK3PXP");
var options = TotpOptions.GoogleAuthenticator;  // SHA1, 30s, 6 digits, ±1 window
var totp    = new TotpGenerator(secret, options);

OtpCode code   = totp.Generate();
var     result = totp.Validate(userInput);

if (result.IsValid)
    Console.WriteLine($"Matched at window offset {result.WindowOffset}");
```

---

## TOTP

### Fluent Builder

```csharp
var options = new TotpOptionsBuilder()
    .WithAlgorithm(OtpAlgorithm.HmacSha256)
    .WithStepSeconds(30)
    .WithDigits(8)
    .WithValidationWindow(1)       // ±1 step (3 codes accepted)
    .WithExtraLookBehind(1)        // 2 steps behind total
    .Build();

var totp = new TotpGenerator(secret, options);
```

### Built-in Presets

```csharp
TotpOptions.Default              // SHA1, 30s, 6 digits, ±1
TotpOptions.GoogleAuthenticator  // Same as Default
TotpOptions.HighSecurity         // SHA256, 30s, 8 digits, strict (0 window)
TotpOptions.MaxSecurity          // SHA512, 30s, 8 digits, strict
TotpOptions.SixtySeconds         // SHA1, 60s, 6 digits, ±1
```

### Debug Window

```csharp
// Inspect all codes in the validation window — useful for diagnosing clock drift
var window = totp.GenerateWindow();
foreach (var (offset, code) in window)
    Console.WriteLine($"Offset {offset,+3}: {code.Code}");
```

---

## HOTP (Counter-Based)

```csharp
using OtpSharper.Hotp;

var store = new InMemoryHotpCounterStore();
var hotp  = new HotpGenerator(secret);

// Generate at a specific counter
OtpCode code = hotp.GenerateAt(counter: 0);  // "755224" (RFC 4226 vector)

// Validate + auto-advance counter in store
var result = await hotp.ValidateAsync("755224", keyId: "user1", store);
if (result.IsValid)
    Console.WriteLine($"Matched counter {result.MatchedCounter}, offset {result.WindowOffset}");
```

### Custom Counter Store (Database Example)

```csharp
public class DbHotpCounterStore : IHotpCounterStore
{
    private readonly MyDbContext _db;

    public async ValueTask<long> GetCounterAsync(string keyId, CancellationToken ct)
        => (await _db.OtpCounters.FindAsync([keyId], ct))?.Counter ?? 0;

    public async ValueTask SetCounterAsync(string keyId, long newCounter, CancellationToken ct)
    {
        var row = await _db.OtpCounters.FindAsync([keyId], ct);
        if (row is null) _db.OtpCounters.Add(new OtpCounter { KeyId = keyId, Counter = newCounter });
        else if (newCounter > row.Counter) row.Counter = newCounter;
        await _db.SaveChangesAsync(ct);
    }
}
```

---

## Steam Guard

```csharp
using OtpSharper.Steam;

var steam = new SteamGuardGenerator(secret);

SteamGuardCode code = steam.Generate();
Console.WriteLine(code.Code);  // e.g. "X3Y2K"

bool valid = steam.Validate(userInput).IsValid;
```

---

## otpauth:// URI

```csharp
using OtpSharper.Uri;

// Build
var uri    = OtpUri.ForTotp("alice@example.com", secret, options, issuer: "MyApp");
string str = uri.ToUriString();
// => otpauth://totp/MyApp:alice%40example.com?secret=...&issuer=MyApp

// Parse
var parsed = OtpUri.Parse("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example");
TotpGenerator totp = parsed.ToTotpGenerator();

// QR Code URL
string qrUrl = uri.ToQrCodeImageUrl(300);
// => https://chart.googleapis.com/chart?chs=300x300&chld=M|0&cht=qr&chl=otpauth%3A%2F%2F...
```

> **Note:** OtpSharper is the only .NET OTP library in this benchmark comparison that includes a built-in `otpauth://` URI parser.

---

## Clock Drift Correction

```csharp
using OtpSharper.Sync;

// Measure drift vs NTP
ClockDriftResult drift = await ClockSync.MeasureDriftAsync("pool.ntp.org");
Console.WriteLine(drift);  // "Drift: +234.5ms vs pool.ntp.org at 2025-01-01T..."

if (drift.IsProblematic)
{
    ITimeProvider corrected = drift.CreateCorrectedTimeProvider();
    var options = new TotpOptions { TimeProvider = corrected };
    var totp    = new TotpGenerator(secret, options);
}

// Or auto-create in one call
ITimeProvider provider = await ClockSync.CreateCorrectedTimeProviderAsync();
```

---

## Dependency Injection

```csharp
// Program.cs / Startup.cs
services.AddTotp("JBSWY3DPEHPK3PXP", options =>
    options.WithAlgorithm(OtpAlgorithm.HmacSha256)
           .WithDigits(8));

// Or from a full otpauth:// URI
services.AddOtpManager("otpauth://totp/App:user@example.com?secret=...");

// Inject
public class AuthService(TotpGenerator totp)
{
    public bool Verify(string code) => totp.Validate(code).IsValid;
}
```

---

## Security & Hardening

### Constant-Time Comparison

Enabled by default to prevent timing oracle attacks. The validator always compares the full code string before returning, regardless of the position of the first differing character.

```csharp
var options = new TotpOptions
{
    UseConstantTimeComparison = true   // default — do not disable in production
};
```

### Pinned Secret Memory

`OtpSecret` allocates a GC-pinned array and zeroes it on `Dispose()`. Always use `using`:

```csharp
using var secret = OtpSecret.FromBase32("JBSWY3DPEHPK3PXP");
// secret bytes are zeroed when the using block exits
```

### Secret Strength Enforcement

```csharp
// Estimate entropy
double bits = OtpSecretGenerator.EstimateEntropyBits(base32Secret);

// Classify
SecretStrength strength = OtpSecretGenerator.AssessStrength(base32Secret);
// Weak (≤80 bits) | Adequate (81–127) | Strong (128–255) | VeryStrong (256+)

// Enforce a minimum — throws CryptographicException if not met
OtpSecretGenerator.EnsureMinimumStrength(base32Secret, minimumBits: 128);

// Generate a correctly-sized secret for an algorithm
OtpSecret secret = OtpSecretGenerator.GenerateForAlgorithm(OtpAlgorithm.HmacSha256);
```

### Brute-Force Backoff

Thread-safe in-memory lockout policy. For distributed deployments, replicate the same logic against a shared cache (e.g., Redis).

```csharp
var policy = new OtpBackoffPolicy(new OtpBackoffOptions
{
    MaxFailedAttempts = 5,
    LockoutDuration   = TimeSpan.FromMinutes(15),
    AttemptWindow     = TimeSpan.FromMinutes(10),
    ResetOnSuccess    = true,
});

// Check before validating
BackoffResult check = policy.CheckAllowed(userId);
if (!check.IsAllowed)
{
    Console.WriteLine($"Locked out until {check.LockoutExpiry}");
    return;
}

bool valid = totp.Validate(userCode).IsValid;
if (valid) policy.RecordSuccess(userId);
else
{
    var result = policy.RecordFailure(userId);
    Console.WriteLine($"{result.RemainingAttempts} attempts remaining");
}
```

### Algorithm Recommendations

| Use Case | Recommended Algorithm | Reason |
|---|---|---|
| Google Authenticator compatibility | SHA1 | RFC-mandated; universal support |
| New systems / higher security | SHA256 | Stronger, still widely supported |
| Maximum security | SHA512 or SHA3-512 | Future-proof; OtpSharper exclusive for SHA3 |

---

## Project Structure

```
OtpSharper/
├── src/
│   └── OtpSharper/
│       ├── Abstractions/
│       │   ├── OtpBackoffPolicy.cs        # Brute-force lockout
│       │   ├── TotpValidationService.cs   # High-level validation service
│       │   └── UsedCodeTracker.cs         # Replay prevention tracker
│       ├── Algorithms/
│       │   ├── HmacProvider.cs            # HMAC-SHA1/256/384/512/SHA3 computation
│       │   └── OtpAlgorithm.cs            # Algorithm enum
│       ├── Core/
│       │   ├── Base32.cs                  # RFC 4648 Base32 codec
│       │   ├── DynamicTruncation.cs       # RFC 4226 §5.3 truncation + constant-time compare
│       │   ├── OtpResults.cs              # OtpCode / OtpValidationResult types
│       │   ├── OtpSecret.cs               # Pinned, zeroed secret container
│       │   ├── OtpSecretGenerator.cs      # Key generation + entropy assessment
│       │   └── TimeProvider.cs            # Abstracted time source
│       ├── Extensions/
│       │   └── ServiceCollectionExtensions.cs  # DI registration helpers
│       ├── Hotp/
│       │   ├── HotpCounterStore.cs        # IHotpCounterStore + in-memory impl
│       │   ├── HotpGenerator.cs           # RFC 4226 HOTP generator + validator
│       │   └── HotpOptions.cs             # HOTP configuration
│       ├── Steam/
│       │   └── SteamGuardGenerator.cs     # Steam Guard 5-char TOTP variant
│       ├── Sync/
│       │   └── ClockSync.cs               # NTP drift measurement + correction
│       ├── Totp/
│       │   ├── TotpGenerator.cs           # RFC 6238 TOTP generator + validator
│       │   ├── TotpOptions.cs             # TOTP configuration + presets
│       │   └── TotpOptionsBuilder.cs      # Fluent options builder
│       ├── Uri/
│       │   └── OtpUri.cs                  # otpauth:// builder, parser, QR URL
│       ├── GlobalUsings.cs
│       ├── OtpManager.cs                  # High-level enrollment + validation facade
│       └── OtpSharper.csproj
├── tests/
│   └── OtpSharper.Tests/
│       ├── AbstractionTests.cs            # Backoff policy tests
│       ├── Base32AndUriTests.cs           # Base32 codec + URI round-trip tests
│       ├── HotpTests.cs                   # RFC 4226 test vectors
│       ├── SteamGuardTests.cs             # Steam Guard output tests
│       ├── TotpTests.cs                   # RFC 6238 test vectors + window tests
│       └── OtpSharper.Tests.csproj
├── OtpSharper.Benchmark/
│   ├── AlgorithmBenchmarks.cs             # Per-algorithm TOTP throughput
│   ├── Base32Benchmarks.cs                # Base32 encode/decode at various key sizes
│   ├── HotpGenerationBenchmarks.cs        # HOTP generation at various counters
│   ├── OtpUriBenchmarks.cs                # URI parse + round-trip
│   ├── SecretKeySetupBenchmarks.cs        # Full cold-path setup + generate
│   ├── TotpGenerationBenchmarks.cs        # Steady-state TOTP generation
│   ├── TotpValidationBenchmarks.cs        # Server-side validation hot path
│   ├── Program.cs
│   └── OtpSharper.Benchmark.csproj
├── OtpSharper.sln
└── LICENSE
```

---

## Benchmarks

Benchmarks compare OtpSharper against [Otp.NET](https://github.com/kspearrin/Otp.NET) (v1.4.1), the most widely-used .NET OTP library. All tests run on .NET 10.0 using [BenchmarkDotNet](https://benchmarkdotnet.org/) 0.15.8 in Release mode with JIT optimizations enforced.

### Running the Benchmarks

```shell
cd OtpSharper.Benchmark
dotnet run -c Release
```

### Results: Secret Key Setup

These benchmarks measure the **cold path** — relevant for stateless APIs that construct the TOTP object on every request rather than caching it.

| Method | Categories | Mean | Error | StdDev | Ratio | RatioSD | Allocated | Alloc Ratio |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Otp.NET | Setup_And_Generate | 2,933.23 ns | 40.393 ns | 35.808 ns | baseline | | 960 B | |
| OtpSharper | Setup_And_Generate | 1,510.06 ns | 14.997 ns | 12.523 ns | 1.94x faster | 0.03x | 736 B | 1.30x less |
| | | | | | | | | |
| Otp.NET | Setup_FromBase32_Generate | 3,233.58 ns | 27.413 ns | 22.891 ns | baseline | | 1008 B | |
| OtpSharper | Setup_FromBase32_Generate | 1,687.82 ns | 22.657 ns | 20.085 ns | 1.92x faster | 0.03x | 784 B | 1.29x less |
| | | | | | | | | |
| Otp.NET | Setup_ObjectCreation | 61.45 ns | 1.529 ns | 1.277 ns | baseline | | 168 B | |
| OtpSharper | Setup_ObjectCreation | 155.67 ns | 6.084 ns | 5.080 ns | 2.53x slower | 0.09x | 192 B | 1.14x more |

### Benchmark Interpretation

#### `Setup_And_Generate` — ~1.94x faster, ~1.30x less memory

This scenario constructs the TOTP object and computes a code in one shot, simulating a **stateless server** that doesn't cache generator instances (a common pattern in microservices and serverless functions). OtpSharper is nearly twice as fast here. In a system processing thousands of 2FA verifications per second, this directly translates to throughput.

#### `Setup_FromBase32_Generate` — ~1.92x faster, ~1.29x less memory

Same as above but starting from a Base32-encoded secret string — the realistic path when a stored secret is read from a database and decoded before use. OtpSharper's combined Base32 decode + HMAC compute pipeline is more efficient than Otp.NET's equivalent. Memory savings (~220 bytes per call) also reduce GC pressure in high-throughput scenarios.

#### `Setup_ObjectCreation` — 2.53x slower, 1.14x more memory

When creating a generator object alone (with no code generation), OtpSharper is slower. This is an intentional trade-off: `OtpSecret` performs **GC pinning** at construction time to protect key material from being moved or scanned in memory. This extra work during object creation pays a small upfront cost that enables the secure zeroing-on-dispose behaviour. For any scenario that actually generates or validates a code — which is every real-world use — the pinning overhead is amortised and OtpSharper wins overall (see the two rows above).

**In short:** OtpSharper is faster where it matters (end-to-end operations) and slower only in the micro-benchmark that isolates pure object allocation — a scenario that never occurs in isolation in production.

---

## Testing

Tests use [xUnit](https://xunit.net/) and [FluentAssertions](https://fluentassertions.com/).

```shell
cd tests/OtpSharper.Tests
dotnet test
```

Test coverage includes:

- **RFC 4226 test vectors** — all 10 HOTP reference values from Appendix D
- **RFC 6238 test vectors** — all 18 TOTP reference values from Appendix B (SHA1, SHA256, SHA512)
- **Validation window** — look-ahead, look-behind, and asymmetric window tests
- **Base32 codec** — encode/decode round-trips, padding, error cases
- **otpauth:// URI** — parse, build, and round-trip for TOTP and HOTP URIs
- **Steam Guard** — expected output for known inputs
- **Backoff policy** — lockout triggering, expiry, reset on success, concurrent access

---

## RFC Compliance

| RFC | Section | Status |
|---|---|---|
| RFC 4226 | §4 Algorithm | ✅ Full |
| RFC 4226 | §5 Dynamic Truncation | ✅ Full |
| RFC 4226 | Appendix D test vectors | ✅ All 10 pass |
| RFC 6238 | §4 TOTP Algorithm | ✅ Full |
| RFC 6238 | §5 Security | ✅ (constant-time, window) |
| RFC 6238 | Appendix B test vectors | ✅ All 18 pass |
| RFC 4648 | Base32 encoding | ✅ Full |
| Google Auth Key URI | `otpauth://` format | ✅ Full |

---

## License

MIT — see [LICENSE](LICENSE) for details.

Copyright © 2026 neo-vortex
