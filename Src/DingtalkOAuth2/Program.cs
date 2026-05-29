using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Tea;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddOptions<OAuth2BridgeOptions>()
    .Bind(builder.Configuration.GetSection("OAuth2Bridge"))
    .ValidateOnStart();

builder.Services.AddSingleton<DingTalkOAuthClient>();
builder.Services.AddProblemDetails();

var app = builder.Build();

app.UseExceptionHandler();

app.MapGet("/", (HttpRequest request) => Results.Ok(new
{
    service = "dingtalk-oauth2",
    issuer = ResolveIssuer(request),
    metadata = $"{ResolveIssuer(request)}/.well-known/oauth-authorization-server"
}));

app.MapGet("/.well-known/oauth-authorization-server", BuildAuthorizationServerMetadata);
app.MapGet("/.well-known/openid-configuration", BuildAuthorizationServerMetadata);

app.MapGet("/authorize", (HttpRequest request, IOptions<OAuth2BridgeOptions> options) =>
{
    var query = request.Query;
    var responseType = query["response_type"].ToString();
    var clientId = query["client_id"].ToString();
    var redirectUri = query["redirect_uri"].ToString();
    var state = query["state"].ToString();

    if (!string.Equals(responseType, "code", StringComparison.Ordinal))
    {
        return AuthorizationError(redirectUri, state, "unsupported_response_type", "Only response_type=code is supported.");
    }

    if (string.IsNullOrWhiteSpace(clientId))
    {
        return AuthorizationError(redirectUri, state, "invalid_request", "client_id is required.");
    }

    if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out _))
    {
        return Results.BadRequest(new OAuthError("invalid_request", "redirect_uri must be an absolute URI."));
    }

    var dingtalkAuthorizationUrl = QueryHelpers.AddQueryString(
        options.Value.AuthorizeEndpoint,
        new Dictionary<string, string?>
        {
            ["redirect_uri"] = redirectUri,
            ["response_type"] = "code",
            ["client_id"] = clientId,
            ["scope"] = string.IsNullOrWhiteSpace(options.Value.DingTalkScope) ? "openid" : options.Value.DingTalkScope,
            ["state"] = state
        });

    return Results.Redirect(dingtalkAuthorizationUrl);
});

app.MapPost("/token", async (
    HttpRequest request,
    IOptions<OAuth2BridgeOptions> options,
    DingTalkOAuthClient dingTalkOAuthClient,
    CancellationToken cancellationToken) =>
{
    var parameters = await ReadRequestParametersAsync(request, cancellationToken);
    var grantType = GetRequired(parameters, "grant_type");
    var code = FirstNonEmpty(GetOptional(parameters, "code"), GetOptional(parameters, "authCode"), GetOptional(parameters, "auth_code"));
    var clientId = GetClientId(request, parameters);
    var clientSecret = GetClientSecret(request, parameters);

    if (!string.Equals(grantType, "authorization_code", StringComparison.Ordinal))
    {
        return Results.BadRequest(new OAuthError("unsupported_grant_type", "Only authorization_code grant is supported."));
    }

    if (string.IsNullOrWhiteSpace(code))
    {
        return Results.BadRequest(new OAuthError("invalid_request", "code is required."));
    }

    if (string.IsNullOrWhiteSpace(clientId))
    {
        return Results.BadRequest(new OAuthError("invalid_client", "client_id is required."));
    }

    if (string.IsNullOrWhiteSpace(clientSecret))
    {
        return Results.BadRequest(new OAuthError("invalid_client", "client_secret is required."));
    }

    try
    {
        var token = await dingTalkOAuthClient.ExchangeAuthorizationCodeAsync(clientId, clientSecret, code, cancellationToken);
        return Results.Ok(new TokenResponse(
            AccessToken: token.AccessToken,
            TokenType: "Bearer",
            ExpiresIn: token.ExpiresIn,
            RefreshToken: token.RefreshToken ?? string.Empty,
            Scope: GetOptional(parameters, "scope"),
            Provider: "dingtalk"));
    }
    catch (DingTalkOAuthException ex)
    {
        return Results.BadRequest(new OAuthError("invalid_grant", ex.Message));
    }
    catch (TeaException)
    {
        return Results.Problem("DingTalk SDK token exchange failed.", statusCode: StatusCodes.Status502BadGateway);
    }
});

app.MapGet("/userinfo", async (
    HttpRequest request,
    DingTalkOAuthClient dingTalkOAuthClient,
    CancellationToken cancellationToken) =>
{
    var accessToken = request.Headers.Authorization.ToString();
    if (accessToken.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
    {
        accessToken = accessToken["Bearer ".Length..].Trim();
    }

    if (string.IsNullOrWhiteSpace(accessToken))
    {
        return Results.Unauthorized();
    }

    try
    {
        var userInfo = await dingTalkOAuthClient.GetUserInfoAsync(accessToken, cancellationToken);
        return Results.Ok(new
        {
            sub = userInfo.UnionId,
            name = FirstNonEmpty(userInfo.Nick, userInfo.UnionId),
            picture = userInfo.AvatarUrl,
            phone_number = userInfo.Mobile,
            email = FirstNonEmpty(userInfo.Email, userInfo.LoginEmail),
            avatarUrl = userInfo.AvatarUrl,
            loginEmail = userInfo.LoginEmail,
            mobile = userInfo.Mobile,
            nick = userInfo.Nick,
            openId = userInfo.OpenId,
            stateCode = userInfo.StateCode,
            unionId = userInfo.UnionId,
            visitor = userInfo.Visitor,
            dingtalk = userInfo
        });
    }
    catch (DingTalkOAuthException ex)
    {
        return Results.BadRequest(new OAuthError("invalid_token", ex.Message));
    }
    catch (TeaException)
    {
        return Results.Problem("DingTalk SDK userinfo request failed.", statusCode: StatusCodes.Status502BadGateway);
    }
});

app.Run();

static IResult BuildAuthorizationServerMetadata(HttpRequest request)
{
    var issuer = ResolveIssuer(request);
    return Results.Ok(new
    {
        issuer,
        authorization_endpoint = $"{issuer}/authorize",
        token_endpoint = $"{issuer}/token",
        userinfo_endpoint = $"{issuer}/userinfo",
        response_types_supported = new[] { "code" },
        grant_types_supported = new[] { "authorization_code" },
        token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" },
        scopes_supported = new[] { "openid", "profile", "email", "phone" },
        claims_supported = new[]
        {
            "sub",
            "name",
            "picture",
            "phone_number",
            "email",
            "avatarUrl",
            "loginEmail",
            "mobile",
            "nick",
            "openId",
            "stateCode",
            "unionId",
            "visitor"
        },
        service_documentation = "https://open.dingtalk.com/document/orgapp/obtain-identity-credentials"
    });
}

static IResult AuthorizationError(string redirectUri, string state, string error, string description)
{
    if (Uri.TryCreate(redirectUri, UriKind.Absolute, out _))
    {
        var callbackUrl = QueryHelpers.AddQueryString(
            redirectUri,
            new Dictionary<string, string?>
            {
                ["error"] = error,
                ["error_description"] = description,
                ["state"] = state
            });

        return Results.Redirect(callbackUrl);
    }

    return Results.BadRequest(new OAuthError(error, description));
}

static async Task<Dictionary<string, string>> ReadRequestParametersAsync(HttpRequest request, CancellationToken cancellationToken)
{
    if (request.HasFormContentType)
    {
        var form = await request.ReadFormAsync(cancellationToken);
        return form.ToDictionary(pair => pair.Key, pair => pair.Value.ToString(), StringComparer.Ordinal);
    }

    if (request.ContentType?.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) == true)
    {
        var body = await JsonSerializer.DeserializeAsync<Dictionary<string, string>>(
            request.Body,
            JsonSerializerOptions.Web,
            cancellationToken);
        return body ?? [];
    }

    return request.Query.ToDictionary(pair => pair.Key, pair => pair.Value.ToString(), StringComparer.Ordinal);
}

static string GetRequired(Dictionary<string, string> parameters, string key) =>
    parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
        ? value
        : string.Empty;

static string GetOptional(Dictionary<string, string> parameters, string key) =>
    parameters.TryGetValue(key, out var value) ? value : string.Empty;

static string GetClientId(HttpRequest request, Dictionary<string, string> parameters)
{
    var (username, _) = ReadBasicCredentials(request);
    return FirstNonEmpty(username, GetOptional(parameters, "client_id"));
}

static string GetClientSecret(HttpRequest request, Dictionary<string, string> parameters)
{
    var (_, password) = ReadBasicCredentials(request);
    return FirstNonEmpty(password, GetOptional(parameters, "client_secret"));
}

static (string Username, string Password) ReadBasicCredentials(HttpRequest request)
{
    var authorization = request.Headers.Authorization.ToString();
    if (!authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
    {
        return (string.Empty, string.Empty);
    }

    try
    {
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(authorization["Basic ".Length..].Trim()));
        var separatorIndex = decoded.IndexOf(':', StringComparison.Ordinal);
        if (separatorIndex < 0)
        {
            return (decoded, string.Empty);
        }

        return (
            Uri.UnescapeDataString(decoded[..separatorIndex]),
            Uri.UnescapeDataString(decoded[(separatorIndex + 1)..]));
    }
    catch (FormatException)
    {
        return (string.Empty, string.Empty);
    }
}

static string FirstNonEmpty(params string?[] values) =>
    values.FirstOrDefault(static value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

static string ResolveIssuer(HttpRequest request) =>
    $"{request.Scheme}://{request.Host}".TrimEnd('/');

sealed class OAuth2BridgeOptions
{
    public string AuthorizeEndpoint { get; set; } = "https://login.dingtalk.com/oauth2/auth";

    public string DingTalkScope { get; set; } = "openid";
}

sealed class DingTalkOAuthClient(ILogger<DingTalkOAuthClient> logger)
{
    public async Task<DingTalkTokenResponse> ExchangeAuthorizationCodeAsync(
        string clientId,
        string clientSecret,
        string authCode,
        CancellationToken cancellationToken)
    {
        var client = CreateOAuth2Client();
        var request = new AlibabaCloud.SDK.Dingtalkoauth2_1_0.Models.GetUserTokenRequest
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            Code = authCode,
            GrantType = "authorization_code"
        };

        // AlibabaCloud SDK does not expose CancellationToken for this API.
        var response = await client.GetUserTokenAsync(request);
        cancellationToken.ThrowIfCancellationRequested();

        var accessToken = response?.Body?.AccessToken;
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            logger.LogWarning("DingTalk GetUserToken returned empty AccessToken. AuthCodeLen={AuthCodeLen}", authCode.Length);
            throw new DingTalkOAuthException("DingTalk token exchange failed.");
        }

        return new DingTalkTokenResponse(
            AccessToken: accessToken,
            ExpiresIn: response?.Body?.ExpireIn ?? 0,
            RefreshToken: response?.Body?.RefreshToken ?? string.Empty);
    }

    public async Task<DingTalkUserInfoResponse> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken)
    {
        var client = CreateContactClient();
        var headers = new AlibabaCloud.SDK.Dingtalkcontact_1_0.Models.GetUserHeaders
        {
            XAcsDingtalkAccessToken = accessToken
        };

        // AlibabaCloud SDK does not expose CancellationToken for this API.
        var response = await client.GetUserWithOptionsAsync(
            "me",
            headers,
            new AlibabaCloud.TeaUtil.Models.RuntimeOptions());
        cancellationToken.ThrowIfCancellationRequested();

        var body = response?.Body;
        if (body is null || string.IsNullOrWhiteSpace(body.UnionId))
        {
            throw new DingTalkOAuthException("DingTalk user info response is empty.");
        }

        return new DingTalkUserInfoResponse(
            UnionId: body.UnionId,
            Nick: body.Nick,
            OpenId: body.OpenId,
            AvatarUrl: body.AvatarUrl,
            StateCode: body.StateCode,
            Mobile: body.Mobile,
            Email: body.Email,
            LoginEmail: body.LoginEmail,
            Visitor: body.Visitor);
    }

    private static AlibabaCloud.SDK.Dingtalkoauth2_1_0.Client CreateOAuth2Client() =>
        new(new AlibabaCloud.OpenApiClient.Models.Config
        {
            Protocol = "https",
            RegionId = "central"
        });

    private static AlibabaCloud.SDK.Dingtalkcontact_1_0.Client CreateContactClient() =>
        new(new AlibabaCloud.OpenApiClient.Models.Config
        {
            Protocol = "https",
            RegionId = "central"
        });
}

sealed class DingTalkOAuthException(string message) : Exception(message);

sealed record OAuthError(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("error_description")] string ErrorDescription);

sealed record TokenResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] long ExpiresIn,
    [property: JsonPropertyName("refresh_token")] string RefreshToken,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("provider")] string Provider);

sealed record DingTalkTokenResponse(string AccessToken, long ExpiresIn, string RefreshToken);

sealed record DingTalkUserInfoResponse(
    string UnionId,
    string? Nick,
    string? OpenId,
    string? AvatarUrl,
    string? StateCode,
    string? Mobile,
    string? Email,
    string? LoginEmail,
    bool? Visitor);
