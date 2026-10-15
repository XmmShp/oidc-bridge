using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace OidcBridge.Oidc;

/// <summary>Version 1: exact UTF-8 input → PBKDF2-SHA512 → HMAC-DRBG-SHA512 → RSA-2048.</summary>
/// <remarks>
/// These parameters and the pinned Bouncy Castle generation algorithm define the key identity.
/// Keep the published test vector unchanged across dependency upgrades. Do not use this DRBG
/// for tickets, correlation values, IVs, or any randomness outside this one key generation.
/// </remarks>
public static class SigningKeyDerivation
{
    public static RSA Derive(string signingKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(signingKey);
        var password = new UTF8Encoding(false, true).GetBytes(signingKey);
        var seed = Rfc2898DeriveBytes.Pbkdf2(password, "oidc-bridge/key-derivation/v1"u8,
            210_000, HashAlgorithmName.SHA512, 64);
        CryptographicOperations.ZeroMemory(password);
        try
        {
            var random = new SP800SecureRandomBuilder(new SeedEntropyProvider(seed[..48]))
                .SetSecurityStrength(256)
                .SetEntropyBitsRequired(384)
                .SetPersonalizationString("oidc-bridge/rsa-2048/v1"u8.ToArray())
                .BuildHMac(new HMac(new Sha512Digest()), seed[48..], predictionResistant: false);
            var generator = new RsaKeyPairGenerator();
            generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), random, 2048, 128));
            var pair = generator.GenerateKeyPair();
            var parameters = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)pair.Private);
            var rsa = RSA.Create();
            try { rsa.ImportParameters(parameters); }
            catch { rsa.Dispose(); throw; }
            finally
            {
                Clear(parameters.D); Clear(parameters.P); Clear(parameters.Q);
                Clear(parameters.DP); Clear(parameters.DQ); Clear(parameters.InverseQ);
            }
            return rsa;
        }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }

    private static void Clear(byte[]? bytes) { if (bytes is not null) CryptographicOperations.ZeroMemory(bytes); }

    private sealed class SeedEntropyProvider(byte[] entropy) : IEntropySourceProvider
    {
        public IEntropySource Get(int bitsRequired)
        {
            if (bitsRequired != 384) throw new InvalidOperationException("Unexpected key derivation entropy size.");
            return new SingleUseEntropy(entropy);
        }
    }

    private sealed class SingleUseEntropy(byte[] entropy) : IEntropySource
    {
        private bool _used;
        public bool IsPredictionResistant => false;
        public int EntropySize => 384;
        public byte[] GetEntropy()
        {
            var result = new byte[48];
            GetEntropy(result);
            return result;
        }

        public int GetEntropy(Span<byte> output)
        {
            // Automatic reseeding from the OS would make deployment keys non-deterministic.
            if (_used) throw new InvalidOperationException("Unexpected reseed during deterministic key generation.");
            _used = true;
            entropy.CopyTo(output);
            CryptographicOperations.ZeroMemory(entropy);
            return 48;
        }
    }
}
