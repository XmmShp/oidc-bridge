using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OidcBridge.Oidc;

// All durable material is deployment configuration. Tickets live only in the browser/client.
public sealed class OidcService : IDisposable
{
    public const string TokenPrefix = "oidc.";
    public static readonly string[] Scopes = ["openid", "profile", "email", "phone"];
    private readonly OidcClientRegistry _clients;
    private readonly TimeProvider _time;
    private readonly RSA _rsa;
    private readonly RsaSecurityKey _key;
    private readonly JsonWebTokenHandler _handler = new() { SetDefaultTimesOnTokenCreation = false, MapInboundClaims = false };

    public DateTime UtcNow => _time.GetUtcNow().UtcDateTime;

    public OidcService(IOptions<OidcBridgeOptions> options, OidcClientRegistry clients, TimeProvider time)
    {
        var settings = options.Value;
        _clients = clients;
        _time = time;
        if (string.IsNullOrEmpty(settings.SigningKey))
            throw InvalidOptions("SigningKey is required and must be a non-empty secret string.");
        if (!Uri.TryCreate(settings.BaseUrl.Trim(), UriKind.Absolute, out var baseUri) ||
            baseUri.Scheme != "https" && !(baseUri.Scheme == "http" && baseUri.IsLoopback))
            throw InvalidOptions("OIDC requires an HTTPS BaseUrl (HTTP loopback is allowed for local development).");
        try { _rsa = SigningKeyDerivation.Derive(settings.SigningKey); }
        catch (ArgumentException)
        { throw InvalidOptions("SigningKey must contain valid Unicode text."); }
        // Do not share providers holding a disposed RSA instance between hosts with the same key id.
        _key = new RsaSecurityKey(_rsa) { CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false } };
        _key.KeyId = Base64UrlEncoder.Encode(_key.ComputeJwkThumbprint());
    }

    public RegisteredOidcClient? FindClient(string provider, string clientId) => _clients.Find(provider, clientId);

    public static bool ValidRedirectUri(string value) => Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
        (uri.Scheme == "https" || uri.Scheme == "http" && uri.IsLoopback) &&
        string.IsNullOrEmpty(uri.Fragment) && string.IsNullOrEmpty(uri.UserInfo);

    public object Jwks()
    {
        var parameters = _rsa!.ExportParameters(false);
        return new { keys = new[] { new { kty = "RSA", use = "sig", alg = "RS256", kid = _key!.KeyId,
            n = Base64UrlEncoder.Encode(parameters.Modulus!), e = Base64UrlEncoder.Encode(parameters.Exponent!) } } };
    }

    public string Seal<T>(string issuer, string purpose, T data, TimeSpan lifetime) => _handler.CreateToken(new SecurityTokenDescriptor
    {
        Issuer = issuer, Audience = $"{issuer}#{purpose}", IssuedAt = UtcNow, NotBefore = UtcNow,
        Expires = UtcNow.Add(lifetime), TokenType = $"bridge-{purpose}+jwt",
        Claims = new Dictionary<string, object> { ["data"] = JsonSerializer.Serialize(data) },
        SigningCredentials = new SigningCredentials(_key!, SecurityAlgorithms.RsaSha256),
        EncryptingCredentials = new EncryptingCredentials(_key!, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512)
    });

    public async Task<T?> UnsealAsync<T>(string issuer, string purpose, string ticket) where T : class
    {
        if (string.IsNullOrWhiteSpace(ticket) || ticket.Length > 32768) return null;
        var result = await _handler.ValidateTokenAsync(ticket, new TokenValidationParameters
        {
            ValidIssuer = issuer, ValidAudience = $"{issuer}#{purpose}", IssuerSigningKey = _key,
            TokenDecryptionKey = _key,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512],
            ValidTypes = [$"bridge-{purpose}+jwt"], RequireSignedTokens = true, RequireExpirationTime = true,
            ClockSkew = TimeSpan.Zero,
            LifetimeValidator = (notBefore, expires, _, _) => expires.HasValue && expires > UtcNow &&
                notBefore.HasValue && notBefore <= UtcNow
        });
        if (!result.IsValid) return null;
        try
        {
            var token = (JsonWebToken)result.SecurityToken;
            if (!token.IsEncrypted || token.Alg != SecurityAlgorithms.RsaOAEP ||
                token.Enc != SecurityAlgorithms.Aes256CbcHmacSha512 || token.InnerToken is null) return null;
            token = token.InnerToken;
            if (token.Alg != SecurityAlgorithms.RsaSha256) return null;
            return JsonSerializer.Deserialize<T>(token.GetClaim("data").Value);
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException) { return null; }
    }

    public string CreateIdToken(string issuer, string clientId, string subject, string nonce, string accessToken,
        IReadOnlyDictionary<string, object> userClaims)
    {
        var claims = new Dictionary<string, object>(userClaims)
        {
            ["sub"] = subject,
            ["at_hash"] = WebEncoders.Base64UrlEncode(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(accessToken))[..16])
        };
        if (!string.IsNullOrEmpty(nonce)) claims["nonce"] = nonce;
        return _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer, Audience = clientId, IssuedAt = UtcNow, NotBefore = UtcNow,
            Expires = UtcNow.AddMinutes(5), Claims = claims,
            SigningCredentials = new SigningCredentials(_key!, SecurityAlgorithms.RsaSha256)
        });
    }

    public static Dictionary<string, object> FilterClaims(JsonElement user, string scope)
    {
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "sub" };
        var scopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (scopes.Contains("profile")) allowed.UnionWith(["name", "family_name", "given_name", "middle_name", "nickname",
            "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"]);
        if (scopes.Contains("email")) allowed.UnionWith(["email", "email_verified"]);
        if (scopes.Contains("phone")) allowed.UnionWith(["phone_number", "phone_number_verified"]);
        return user.EnumerateObject().Where(property => allowed.Contains(property.Name) &&
                property.Value.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined))
            .ToDictionary(property => property.Name, property => (object)property.Value.Clone());
    }

    private static OptionsValidationException InvalidOptions(string message) => new(nameof(OidcBridgeOptions), typeof(OidcBridgeOptions), [message]);
    public void Dispose() => _rsa.Dispose();
}

internal sealed record OidcTransaction(string ClientId, string RedirectUri, string State, string Scope, string Nonce,
    string CodeChallenge, string CorrelationId, string CorrelationHash, string UpstreamVerifier);
internal sealed record OidcCode(OidcTransaction Transaction, string UpstreamCode);
internal sealed record OidcAccess(string ClientId, string UpstreamToken, string Subject, string Scope);
