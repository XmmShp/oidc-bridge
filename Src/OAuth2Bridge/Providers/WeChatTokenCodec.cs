using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace OAuth2Bridge.Providers;

// WeChat requires openid in addition to its access token for userinfo. Protect that pair
// instead of asking downstream OAuth clients to submit non-standard userinfo parameters.
public sealed class WeChatTokenCodec(IDataProtectionProvider protection, TimeProvider time)
{
    public string Encode(string provider, WeChatToken token) => Protector(provider).Protect(JsonSerializer.Serialize(token));

    public WeChatToken Decode(string provider, string token)
    {
        try
        {
            var decoded = JsonSerializer.Deserialize<WeChatToken>(Protector(provider).Unprotect(token));
            if (decoded is null || decoded.ExpiresAt <= time.GetUtcNow() ||
                string.IsNullOrWhiteSpace(decoded.AccessToken) || string.IsNullOrWhiteSpace(decoded.OpenId))
                throw new OAuthProviderException("invalid_token", "The WeChat bridge token is invalid or expired.");
            return decoded;
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException or FormatException)
        {
            throw new OAuthProviderException("invalid_token", "The WeChat bridge token is invalid or expired.");
        }
    }

    private IDataProtector Protector(string provider) => protection.CreateProtector("oauth2-bridge", "wechat-token", provider, "v1");
}

public sealed record WeChatToken(string AccessToken, string OpenId, string? Scope, DateTimeOffset ExpiresAt);
