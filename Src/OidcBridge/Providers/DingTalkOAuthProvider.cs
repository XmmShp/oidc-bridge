using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace OidcBridge.Providers;

public sealed class DingTalkOAuthProvider(HttpClient client, IConfiguration? configuration = null) : IOAuthProvider
{
    private const string AuthorizeEndpoint = "https://login.dingtalk.com/oauth2/auth";
    private const string TokenEndpoint = "https://api.dingtalk.com/v1.0/oauth2/userAccessToken";
    private const string UserInfoEndpoint = "https://api.dingtalk.com/v1.0/contact/users/me";
    private readonly DingTalkOrganization? organization = DingTalkOrganization.FromConfiguration(client, configuration);

    public string Name => "dingtalk";
    public IReadOnlyList<string> Scopes => ["openid", "corpid"];
    public IReadOnlyList<string> Claims => ["sub", "name", "picture", "phone_number", "email", "email_verified", "avatarUrl", "loginEmail", "mobile", "nick", "openId", "stateCode", "unionId", "visitor"];
    public string Documentation => "https://open.dingtalk.com/document/orgapp/obtain-identity-credentials";

    public string BuildAuthorizationUrl(AuthorizationRequest request)
    {
        if (!string.IsNullOrEmpty(request.CodeChallenge))
            throw new OAuthProviderException("invalid_request", "DingTalk does not support PKCE through this bridge.");
        return QueryHelpers.AddQueryString(AuthorizeEndpoint, new Dictionary<string, string?>
        {
            ["client_id"] = request.ClientId,
            ["redirect_uri"] = request.RedirectUri,
            ["response_type"] = "code",
            ["prompt"] = "consent",
            ["scope"] = organization is not null ? "openid corpid" : string.IsNullOrWhiteSpace(request.Scope) ? "openid" : request.Scope,
            ["state"] = request.State
        });
    }

    public async Task<ProviderToken> ExchangeAuthorizationCodeAsync(TokenRequest request, CancellationToken cancellationToken)
    {
        using var response = await client.PostAsJsonAsync(TokenEndpoint, new
        {
            clientId = request.ClientId,
            clientSecret = request.ClientSecret,
            code = request.Code,
            grantType = "authorization_code"
        }, cancellationToken);
        using var document = await ReadResponseAsync(response, "invalid_grant", cancellationToken);
        var data = document.RootElement;
        if (organization is not null && String(data, "corpId") != organization.CorpId)
        {
            throw new OAuthProviderException("invalid_grant", "DingTalk authorization did not select the configured organization.");
        }
        var accessToken = String(data, "accessToken");
        if (string.IsNullOrWhiteSpace(accessToken)) throw new JsonException("Missing DingTalk access token.");
        if (!data.TryGetProperty("expireIn", out var expiry) || expiry.ValueKind != JsonValueKind.Number ||
            !expiry.TryGetInt64(out var seconds) || seconds <= 0)
            throw new JsonException("Invalid DingTalk token lifetime.");
        return new ProviderToken(accessToken, seconds, String(data, "refreshToken"));
    }

    public async Task<object> GetAuthorizationProfileAsync(ProviderToken token, TokenRequest request, CancellationToken cancellationToken)
    {
        using var document = await ReadUserAsync(token.AccessToken, cancellationToken);
        var user = document.RootElement;
        var verifiedEmail = organization is null ? null :
            await organization.ReadVerifiedEmailAsync(request, Subject(user), cancellationToken);
        return MapUser(user, verifiedEmail);
    }

    public async Task<object> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken)
    {
        using var document = await ReadUserAsync(accessToken, cancellationToken);
        return MapUser(document.RootElement, null);
    }

    private async Task<JsonDocument> ReadUserAsync(string accessToken, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, UserInfoEndpoint);
        request.Headers.Add("x-acs-dingtalk-access-token", accessToken);
        using var response = await client.SendAsync(request, cancellationToken);
        return await ReadResponseAsync(response, "invalid_token", cancellationToken);
    }

    private static string Subject(JsonElement user) => String(user, "unionId") is { Length: > 0 } value && !string.IsNullOrWhiteSpace(value)
        ? value : throw new JsonException("Missing DingTalk subject.");

    private object MapUser(JsonElement user, string? verifiedEmail)
    {
        var subject = Subject(user);
        return new
        {
            sub = subject,
            name = OAuthRequestHelpers.FirstNonEmpty(String(user, "nick"), subject),
            picture = String(user, "avatarUrl"),
            phone_number = String(user, "mobile"),
            email = organization is null ? OAuthRequestHelpers.FirstNonEmpty(String(user, "email"), String(user, "loginEmail")) : verifiedEmail,
            email_verified = verifiedEmail is null ? (bool?)null : true,
            avatarUrl = String(user, "avatarUrl"),
            loginEmail = String(user, "loginEmail"),
            mobile = String(user, "mobile"),
            nick = String(user, "nick"),
            openId = String(user, "openId"),
            stateCode = String(user, "stateCode"),
            unionId = subject,
            visitor = user.TryGetProperty("visitor", out var visitor) && visitor.ValueKind is JsonValueKind.True or JsonValueKind.False
                ? (bool?)visitor.GetBoolean() : null,
            dingtalk = user.Clone()
        };
    }

    private static async Task<JsonDocument> ReadResponseAsync(HttpResponseMessage response, string defaultError, CancellationToken cancellationToken)
    {
        if ((int)response.StatusCode >= 500 || response.StatusCode == HttpStatusCode.TooManyRequests)
            throw new HttpRequestException("DingTalk is unavailable.");
        // Keep upstream error bodies out of downstream responses; they may contain sensitive data.
        if (!response.IsSuccessStatusCode)
            throw new OAuthProviderException(defaultError == "invalid_grant" && response.StatusCode == HttpStatusCode.Unauthorized
                ? "invalid_client" : defaultError, "DingTalk rejected the request.");
        var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            document.Dispose();
            throw new JsonException("Invalid DingTalk response.");
        }
        if (root.TryGetProperty("code", out var code) && code.ToString() != "0")
        {
            document.Dispose();
            throw new OAuthProviderException(defaultError, "DingTalk rejected the request.");
        }
        return document;
    }

    private static string? String(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
