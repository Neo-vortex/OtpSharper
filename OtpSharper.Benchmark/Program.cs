using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Exporters.Csv;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Validators;
using OtpSharp.Benchmarks;
using OtpSharper.Benchmark;

Console.WriteLine(Environment.GetEnvironmentVariable("PATH"));
Console.WriteLine(Environment.GetEnvironmentVariable("DOTNET_ROOT"));


// ── Configuration ─────────────────────────────────────────────────────────────
var config = DefaultConfig.Instance
    .AddJob(
        Job.Default
            .WithId("NET10")
            .WithWarmupCount(3)
            .WithIterationCount(15)
            .WithInvocationCount(512)     // multiple invocations per iteration for short ops
            .WithUnrollFactor(16)
    )
    .AddDiagnoser(MemoryDiagnoser.Default)
    .AddExporter(MarkdownExporter.GitHub)
    .AddExporter(CsvMeasurementsExporter.Default)
    .AddValidator(JitOptimizationsValidator.FailOnError)   // ensures Release build
    .WithSummaryStyle(BenchmarkDotNet.Reports.SummaryStyle.Default
        .WithRatioStyle(BenchmarkDotNet.Columns.RatioStyle.Trend));

// ── Run all benchmark classes ─────────────────────────────────────────────────
Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
Console.WriteLine("║          OtpSharper vs Otp.NET — BenchmarkDotNet Suite        ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
Console.WriteLine();

var switcher = new BenchmarkSwitcher(
[
    typeof(TotpGenerationBenchmarks),
    typeof(TotpValidationBenchmarks),
    typeof(HotpGenerationBenchmarks),
    typeof(Base32Benchmarks),
    typeof(OtpUriBenchmarks),
    typeof(AlgorithmBenchmarks),
    typeof(SecretKeySetupBenchmarks),
]);

switcher.RunAll( config);
