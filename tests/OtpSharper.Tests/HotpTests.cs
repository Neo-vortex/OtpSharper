using FluentAssertions;
using OtpSharper.Core;
using OtpSharper.Hotp;
using Xunit;

namespace OtpSharper.Tests;

/// <summary>
/// RFC 4226 Appendix D test vectors.
/// Secret: ASCII "12345678901234567890"
/// </summary>
public class HotpRfc4226Tests
{
    private static readonly byte[] SecretBytes = "12345678901234567890"u8.ToArray();

    /// <summary>RFC 4226 Appendix D Table 1 — first 10 HOTP values.</summary>
    public static TheoryData<long, string> Rfc4226Vectors => new()
    {
        { 0, "755224" },
        { 1, "287082" },
        { 2, "359152" },
        { 3, "969429" },
        { 4, "338314" },
        { 5, "254676" },
        { 6, "287922" },
        { 7, "162583" },
        { 8, "399871" },
        { 9, "520489" },
    };

    [Theory]
    [MemberData(nameof(Rfc4226Vectors))]
    public void GenerateAt_MatchesRfc4226Vectors(long counter, string expected)
    {
        using var secret = new OtpSecret(SecretBytes);
        var hotp = new HotpGenerator(secret);

        OtpCode code = hotp.GenerateAt(counter);

        code.Code.Should().Be(expected,
            $"RFC 4226 vector: counter={counter}");
    }

    [Fact]
    public void ValidateAt_AcceptsCorrectCode()
    {
        using var secret = new OtpSecret(SecretBytes);
        var hotp = new HotpGenerator(secret);

        var result = hotp.ValidateAt("755224", counter: 0);

        result.IsValid.Should().BeTrue();
        result.MatchedCounter.Should().Be(0);
    }

    [Fact]
    public void ValidateAt_RejectsWrongCode()
    {
        using var secret = new OtpSecret(SecretBytes);
        var hotp = new HotpGenerator(secret);

        hotp.ValidateAt("000000", counter: 0).IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task ValidateAsync_AdvancesCounter()
    {
        using var secret = new OtpSecret(SecretBytes);
        var store = new InMemoryHotpCounterStore();
        var hotp  = new HotpGenerator(secret);

        // Counter starts at 0, code at 0 is "755224"
        var result = await hotp.ValidateAsync("755224", "user1", store);

        result.IsValid.Should().BeTrue();

        // Store should now be at 1
        long counter = await store.GetCounterAsync("user1");
        counter.Should().Be(1);
    }

    [Fact]
    public async Task ValidateAsync_HandlesLookAhead()
    {
        using var secret = new OtpSecret(SecretBytes);
        var store = new InMemoryHotpCounterStore();
        var options = new HotpOptions { LookAheadWindow = 5 };
        var hotp = new HotpGenerator(secret, options);

        // Counter is at 0 but user submits code for counter 3
        var result = await hotp.ValidateAsync("969429", "user1", store);

        result.IsValid.Should().BeTrue();
        result.WindowOffset.Should().Be(3);

        // Store should be at 4 (one past matched)
        long counter = await store.GetCounterAsync("user1");
        counter.Should().Be(4);
    }

    [Fact]
    public async Task ValidateAsync_RejectsCounter_OneStepBeyondLookAheadWindow()
    {
        using var secret = new OtpSecret(SecretBytes);
        var store = new InMemoryHotpCounterStore();
        var options = new HotpOptions { LookAheadWindow = 5 };
        var hotp = new HotpGenerator(secret, options);

        // Counter is at 0; a code for counter 6 is one step past the look-ahead window of 5.
        string codeAtOffset6 = hotp.GenerateAt(6).Code;

        var result = await hotp.ValidateAsync(codeAtOffset6, "user1", store);

        result.IsValid.Should().BeFalse();
        (await store.GetCounterAsync("user1")).Should().Be(0, "no match means the counter must not advance");
    }

    [Fact]
    public async Task ValidateAsync_AcceptsCounter_AtExactLookAheadBoundary()
    {
        using var secret = new OtpSecret(SecretBytes);
        var store = new InMemoryHotpCounterStore();
        var options = new HotpOptions { LookAheadWindow = 5 };
        var hotp = new HotpGenerator(secret, options);

        // Counter is at 0; a code for counter 5 is exactly at the edge of the look-ahead window.
        string codeAtOffset5 = hotp.GenerateAt(5).Code;

        var result = await hotp.ValidateAsync(codeAtOffset5, "user1", store);

        result.IsValid.Should().BeTrue();
        result.WindowOffset.Should().Be(5);
        (await store.GetCounterAsync("user1")).Should().Be(6);
    }

    [Fact]
    public async Task ValidateAsync_RejectsReplayedCode()
    {
        using var secret = new OtpSecret(SecretBytes);
        var store = new InMemoryHotpCounterStore();
        var hotp  = new HotpGenerator(secret);

        // First use — OK
        await hotp.ValidateAsync("755224", "user1", store);

        // Replay the same code — must fail (counter advanced)
        var result = await hotp.ValidateAsync("755224", "user1", store);
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void GenerateRange_ProducesCorrectSequence()
    {
        using var secret = new OtpSecret(SecretBytes);
        var hotp = new HotpGenerator(secret);

        var codes = hotp.GenerateRange(0, 10);

        codes.Should().HaveCount(10);
        codes[0].Code.Should().Be("755224");
        codes[9].Code.Should().Be("520489");
    }
}
