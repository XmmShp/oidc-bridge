using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace OAuth2Bridge.Providers;

public sealed class FeishuOAuthProvider(HttpClient client) : IOAuthProvider
{
    private const string AuthorizeEndpoint = "https://accounts.feishu.cn/open-apis/authen/v1/authorize";
    private const string TokenEndpoint = "https://accounts.feishu.cn/oauth/v3/token";
    private const string UserInfoEndpoint = "https://open.feishu.cn/open-apis/authen/v1/user_info";

    public string Name => "feishu";
    public IReadOnlyList<string> CodeChallengeMethods => ["S256", "plain"];
    public IReadOnlyList<string> Scopes => [];
    public IReadOnlyList<string> Claims => ["sub", "name", "picture", "email", "phone_number", "open_id", "union_id", "user_id"];
    public string Documentation => "https://open.feishu.cn/document/authentication-management/access-token/get-user-access-token-v3";

    public string BuildAuthorizationUrl(AuthorizationRequest request)
    {
        var parameters = new Dictionary<string, string?>
        {
            ["client_id"] = request.ClientId,
            ["response_type"] = "code",
            ["redirect_uri"] = request.RedirectUri,
            ["state"] = request.State
        };
        if (!string.IsNullOrWhiteSpace(request.Scope)) parameters["scope"] = request.Scope;
        if (!string.IsNullOrEmpty(request.CodeChallenge))
        {
            if (request.CodeChallengeMethod is not ("" or "plain" or "S256"))
                throw new OAuthProviderException("invalid_request", "Unsupported code_challenge_method.");
            parameters["code_challenge"] = request.CodeChallenge;
            parameters["code_challenge_method"] = string.IsNullOrEmpty(request.CodeChallengeMethod) ? "plain" : request.CodeChallengeMethod;
        }
        if (!string.IsNullOrEmpty(request.Prompt)) parameters["prompt"] = request.Prompt;
        return QueryHelpers.AddQueryString(AuthorizeEndpoint, parameters);
    }

    public async Task<ProviderToken> ExchangeAuthorizationCodeAsync(TokenRequest request, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(request.RedirectUri, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.Fragment))
            throw new OAuthProviderException("invalid_request", "redirect_uri is required and must match the authorization request.");
        var parameters = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = request.ClientId,
            ["client_secret"] = request.ClientSecret,
            ["code"] = request.Code,
            ["redirect_uri"] = request.RedirectUri
        };
        if (!string.IsNullOrEmpty(request.CodeVerifier)) parameters["code_verifier"] = request.CodeVerifier;
        using var response = await client.PostAsJsonAsync(TokenEndpoint, parameters, cancellationToken);
        using var document = await ReadResponseAsync(response, "invalid_grant", cancellationToken);
        var root = document.RootElement;
        var accessToken = String(root, "access_token");
        if (string.IsNullOrWhiteSpace(accessToken)) throw new JsonException("Missing Feishu access token.");
        if (!root.TryGetProperty("expires_in", out var expiry) || expiry.ValueKind != JsonValueKind.Number ||
            !expiry.TryGetInt64(out var seconds) || seconds <= 0)
            throw new JsonException("Invalid Feishu token lifetime.");
        return new ProviderToken(accessToken,
            seconds,
            String(root, "refresh_token"), String(root, "scope"), String(root, "token_type") ?? "Bearer");
    }

    public async Task<object> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var response = await client.SendAsync(request, cancellationToken);
        using var document = await ReadResponseAsync(response, "invalid_token", cancellationToken);
        if (!document.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Object)
            throw new JsonException("Missing Feishu user info.");
        // open_id is always application-scoped; do not change the subject depending on optional permissions.
        var subject = String(data, "open_id");
        if (string.IsNullOrWhiteSpace(subject)) throw new JsonException("Missing Feishu subject.");
        return new
        {
            sub = subject,
            name = String(data, "name"),
            picture = String(data, "avatar_url"),
            email = OAuthRequestHelpers.FirstNonEmpty(String(data, "email"), String(data, "enterprise_email")),
            phone_number = String(data, "mobile"),
            open_id = subject,
            union_id = String(data, "union_id"),
            user_id = String(data, "user_id"),
            feishu = data.Clone()
        };
    }

    private static async Task<JsonDocument> ReadResponseAsync(HttpResponseMessage response, string defaultError, CancellationToken cancellationToken)
    {
        // Do not expose upstream response bodies, which can contain tokens or credentials.
        if ((int)response.StatusCode >= 500 || response.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
            throw new HttpRequestException("Feishu is unavailable.");
        var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            document.Dispose();
            throw new JsonException("Invalid Feishu response.");
        }
        if (!response.IsSuccessStatusCode || root.TryGetProperty("error", out _) ||
            root.TryGetProperty("code", out var code) && code.ToString() != "0")
        {
            var error = String(root, "error");
            document.Dispose();
            if (error is "server_error" or "temporarily_unavailable")
                throw new HttpRequestException("Feishu is unavailable.");
            throw new OAuthProviderException(error is "invalid_client" or "invalid_grant" or "invalid_scope" or "invalid_request" ? error : defaultError,
                defaultError == "invalid_token" ? "Feishu rejected the access token." : "Feishu rejected the token request.");
        }
        return document;
    }

    private static string? String(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
