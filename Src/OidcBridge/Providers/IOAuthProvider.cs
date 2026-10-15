using System.Text.Json.Serialization;

namespace OidcBridge.Providers;

public interface IOAuthProvider
{
    string Name { get; }
    IReadOnlyList<string> Scopes { get; }
    IReadOnlyList<string> Claims { get; }
    IReadOnlyList<string> CodeChallengeMethods => [];
    string Documentation { get; }
    string BuildAuthorizationUrl(AuthorizationRequest request);
    Task<ProviderToken> ExchangeAuthorizationCodeAsync(TokenRequest request, CancellationToken cancellationToken);
    Task<object> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken);
}

public sealed record AuthorizationRequest(string ClientId, string RedirectUri, string State, string Scope,
    string CodeChallenge, string CodeChallengeMethod, string Prompt);
public sealed record TokenRequest(string ClientId, string ClientSecret, string Code, string RedirectUri, string CodeVerifier);
public sealed record ProviderToken(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("expires_in"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? ExpiresIn,
    [property: JsonPropertyName("refresh_token"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RefreshToken = null,
    [property: JsonPropertyName("scope"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Scope = null,
    [property: JsonPropertyName("token_type")] string TokenType = "Bearer");
public sealed class OAuthProviderException(string error, string message) : Exception(message)
{
    public string Error { get; } = error;
}
