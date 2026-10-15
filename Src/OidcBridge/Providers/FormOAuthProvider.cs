using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace OidcBridge.Providers;

public abstract class FormOAuthProvider(HttpClient client) : IOAuthProvider
{
    protected HttpClient Client => client;
    protected abstract string AuthorizeEndpoint { get; }
    protected abstract string TokenEndpoint { get; }
    protected virtual string DefaultScope => string.Empty;
    protected virtual bool CommaSeparatedScope => false;
    protected virtual bool CommaSeparatedTokenScope => CommaSeparatedScope;
    protected virtual bool SupportsPrompt => false;
    public abstract string Name { get; }
    public virtual IReadOnlyList<string> Scopes => [];
    public virtual IReadOnlyList<string> CodeChallengeMethods => [];
    public virtual IReadOnlyList<string> Claims => ["sub", "name", "preferred_username", "picture", "email"];
    public abstract string Documentation { get; }

    public virtual string BuildAuthorizationUrl(AuthorizationRequest request)
    {
        var parameters = new Dictionary<string, string?>
        {
            ["response_type"] = "code", ["client_id"] = request.ClientId,
            ["redirect_uri"] = request.RedirectUri, ["state"] = request.State
        };
        var scope = string.IsNullOrWhiteSpace(request.Scope) ? DefaultScope : request.Scope;
        if (!string.IsNullOrWhiteSpace(scope)) parameters["scope"] = CommaSeparatedScope ? scope.Replace(' ', ',') : scope;
        if (!string.IsNullOrEmpty(request.CodeChallenge))
        {
            var method = string.IsNullOrEmpty(request.CodeChallengeMethod) ? "plain" : request.CodeChallengeMethod;
            if (!CodeChallengeMethods.Contains(method))
                throw new OAuthProviderException("invalid_request", "This provider does not support the requested PKCE method.");
            parameters["code_challenge"] = request.CodeChallenge;
            parameters["code_challenge_method"] = method;
        }
        if (SupportsPrompt && !string.IsNullOrEmpty(request.Prompt)) parameters["prompt"] = request.Prompt;
        return QueryHelpers.AddQueryString(AuthorizeEndpoint, parameters);
    }

    public virtual async Task<ProviderToken> ExchangeAuthorizationCodeAsync(TokenRequest request, CancellationToken cancellationToken)
    {
        ProviderHttp.RequireRedirectUri(request);
        var parameters = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["client_id"] = request.ClientId,
            ["client_secret"] = request.ClientSecret, ["code"] = request.Code, ["redirect_uri"] = request.RedirectUri
        };
        if (!string.IsNullOrEmpty(request.CodeVerifier))
        {
            if (CodeChallengeMethods.Count == 0)
                throw new OAuthProviderException("invalid_request", "This provider does not support PKCE through this bridge.");
            parameters["code_verifier"] = request.CodeVerifier;
        }
        using var message = ProviderHttp.Request(HttpMethod.Post, TokenEndpoint);
        message.Content = new FormUrlEncodedContent(parameters);
        using var response = await client.SendAsync(message, cancellationToken);
        using var document = await ProviderHttp.ReadAsync(response, "invalid_grant", cancellationToken);
        return ProviderHttp.Token(document.RootElement, CommaSeparatedTokenScope);
    }

    public abstract Task<object> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken);

    protected async Task<JsonDocument> GetJsonAsync(string endpoint, string token, CancellationToken cancellationToken)
    {
        using var request = ProviderHttp.Request(HttpMethod.Get, endpoint, token);
        using var response = await client.SendAsync(request, cancellationToken);
        return await ProviderHttp.ReadAsync(response, "invalid_token", cancellationToken);
    }
}
