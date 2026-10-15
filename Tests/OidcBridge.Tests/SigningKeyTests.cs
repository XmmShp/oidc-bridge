using System.Security.Cryptography;
using OidcBridge.Oidc;

namespace OidcBridge.Tests;

public sealed class SigningKeyTests
{
    [Fact]
    public void VersionOne_HasFixedPublicKeyVector()
    {
        using var rsa = SigningKeyDerivation.Derive("oidc-bridge deterministic key test vector v1");
        // This public fingerprint catches changes in KDF parameters, DRBG use, or RSA generation.
        Assert.Equal("6C4C8426D9DBAE329F2D80909BE52159E94760891816A34CFDD74214FDA2512A",
            Convert.ToHexString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo())));
        Assert.Equal(2048, rsa.KeySize);
    }

    [Theory]
    [InlineData("a")]
    [InlineData("任意字符串 🔑")]
    [InlineData("  leading and trailing whitespace  ")]
    [InlineData(" ")]
    [InlineData("not a PEM private key\nwith a newline")]
    public void ArbitraryNonEmptyStrings_ReproduceTheEntirePrivateKey(string seed)
    {
        using var first = SigningKeyDerivation.Derive(seed);
        using var second = SigningKeyDerivation.Derive(seed);
        Assert.True(first.ExportPkcs8PrivateKey().AsSpan().SequenceEqual(second.ExportPkcs8PrivateKey()));
        var message = "independent instance verification"u8;
        var signature = first.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(second.VerifyData(message, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Theory]
    [InlineData("seed", "different seed")]
    [InlineData("seed", " seed")]
    [InlineData("seed", "seed ")]
    [InlineData("é", "e\u0301")]
    public void InputIsExact_WithoutTrimmingOrUnicodeNormalization(string firstSeed, string secondSeed)
    {
        using var first = SigningKeyDerivation.Derive(firstSeed);
        using var second = SigningKeyDerivation.Derive(secondSeed);
        Assert.False(first.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(second.ExportSubjectPublicKeyInfo()));
    }

    [Fact]
    public void EmptySeed_IsRejected()
    {
        Assert.Throws<ArgumentException>(() => SigningKeyDerivation.Derive(""));
        Assert.Throws<ArgumentNullException>(() => SigningKeyDerivation.Derive(null!));
    }
}
