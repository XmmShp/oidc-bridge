using System.Text.Json;
using OAuth2Bridge.Providers;
using static OAuth2Bridge.OAuthRequestHelpers;

namespace OAuth2Bridge;

internal static class OAuthEndpoints
{
    public static void MapOAuthEndpoints(this WebApplication app)
    {
        Map(app.MapGroup("/{provider}"));
        app.MapGet("/.well-known/oauth-authorization-server/{provider}", Metadata);
    }

    private static void Map(RouteGroupBuilder group)
    {
        group.MapGet("/.well-known/oauth-authorization-server", Metadata);
        group.MapGet("/authorize", Authorize);
        group.MapPost("/token", Token);
        group.MapGet("/userinfo", UserInfo);
    }

    private static IOAuthProvider? Resolve(HttpRequest request, OAuthProviderRegistry providers) =>
        providers.Find(request.RouteValues["provider"]?.ToString());

    private static IResult Metadata(HttpRequest request, OAuthProviderRegistry providers)
    {
        var provider = Resolve(request, providers);
        if (provider is null) return Results.NotFound();
        var issuer = $"{ResolveBaseUrl(providers.Options)}/{provider.Name}";
        return Results.Ok(new
        {
            issuer,
            authorization_endpoint = $"{issuer}/authorize",
            token_endpoint = $"{issuer}/token",
            userinfo_endpoint = $"{issuer}/userinfo",
            response_types_supported = new[] { "code" },
            grant_types_supported = new[] { "authorization_code" },
            code_challenge_methods_supported = provider.CodeChallengeMethods,
            token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" },
            scopes_supported = provider.Scopes,
            claims_supported = provider.Claims,
            service_documentation = provider.Documentation
        });
    }

    private static IResult Authorize(HttpRequest request, OAuthProviderRegistry providers)
    {
        var provider = Resolve(request, providers);
        if (provider is null) return Results.NotFound();
        var query = request.Query;
        var redirectUri = query["redirect_uri"].ToString();
        var state = query["state"].ToString();
        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.Fragment))
            return Results.BadRequest(new OAuthError("invalid_request", "redirect_uri must be an absolute URI without a fragment."));
        if (query["response_type"] != "code")
            return AuthorizationError(redirectUri, state, "unsupported_response_type", "Only response_type=code is supported.");
        if (string.IsNullOrWhiteSpace(query["client_id"]))
            return AuthorizationError(redirectUri, state, "invalid_request", "client_id is required.");
        try
        {
            return Results.Redirect(provider.BuildAuthorizationUrl(new AuthorizationRequest(
                query["client_id"].ToString(), redirectUri, state, query["scope"].ToString(),
                query["code_challenge"].ToString(), query["code_challenge_method"].ToString(), query["prompt"].ToString())));
        }
        catch (OAuthProviderException ex)
        {
            return AuthorizationError(redirectUri, state, ex.Error, ex.Message);
        }
    }

    private static async Task<IResult> Token(HttpRequest request, HttpResponse response, OAuthProviderRegistry providers,
        CancellationToken cancellationToken)
    {
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";
        var provider = Resolve(request, providers);
        if (provider is null) return Results.NotFound();
        Dictionary<string, string> parameters;
        try { parameters = await ReadRequestParametersAsync(request, cancellationToken); }
        catch (Exception ex) when (ex is JsonException or InvalidDataException or BadHttpRequestException)
        { return Results.BadRequest(new OAuthError("invalid_request", "Malformed token request.")); }
        if (GetRequired(parameters, "grant_type") != "authorization_code")
            return Results.BadRequest(new OAuthError("unsupported_grant_type", "Only authorization_code grant is supported."));
        var code = FirstNonEmpty(GetOptional(parameters, "code"), GetOptional(parameters, "authCode"), GetOptional(parameters, "auth_code"));
        if (string.IsNullOrWhiteSpace(code))
            return Results.BadRequest(new OAuthError("invalid_request", "code is required."));
        var clientId = GetClientId(request, parameters);
        var clientSecret = GetClientSecret(request, parameters);
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
        {
            var error = new OAuthError("invalid_client", string.IsNullOrWhiteSpace(clientId) ? "client_id is required." : "client_secret is required.");
            if (request.Headers.ContainsKey("Authorization"))
            {
                response.Headers.WWWAuthenticate = "Basic realm=\"oauth2-bridge\"";
                return Results.Json(error, statusCode: StatusCodes.Status401Unauthorized);
            }
            return Results.BadRequest(error);
        }
        if (request.Headers.ContainsKey("Authorization") &&
            (!string.IsNullOrEmpty(GetOptional(parameters, "client_id")) || !string.IsNullOrEmpty(GetOptional(parameters, "client_secret"))))
            return Results.BadRequest(new OAuthError("invalid_request", "Use only one client authentication method."));
        try
        {
            var token = await provider.ExchangeAuthorizationCodeAsync(new TokenRequest(clientId, clientSecret, code,
                GetOptional(parameters, "redirect_uri"), GetOptional(parameters, "code_verifier")), cancellationToken);
            return Results.Ok(token);
        }
        catch (OAuthProviderException ex) { return Results.BadRequest(new OAuthError(ex.Error, ex.Message)); }
        catch (Exception ex) when (ex is HttpRequestException or JsonException || ex is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        { return Results.Problem("Upstream token exchange failed.", statusCode: StatusCodes.Status502BadGateway); }
    }

    private static async Task<IResult> UserInfo(HttpRequest request, HttpResponse response, OAuthProviderRegistry providers,
        CancellationToken cancellationToken)
    {
        var provider = Resolve(request, providers);
        if (provider is null) return Results.NotFound();
        var authorization = request.Headers.Authorization.ToString();
        if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(authorization[7..]))
        {
            response.Headers.WWWAuthenticate = "Bearer";
            return Results.Unauthorized();
        }
        try { return Results.Ok(await provider.GetUserInfoAsync(authorization[7..].Trim(), cancellationToken)); }
        catch (OAuthProviderException ex)
        {
            response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";
            return Results.Json(new OAuthError(ex.Error, ex.Message), statusCode: StatusCodes.Status401Unauthorized);
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException || ex is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        { return Results.Problem("Upstream userinfo request failed.", statusCode: StatusCodes.Status502BadGateway); }
    }
}

internal sealed record OAuthError(
    [property: System.Text.Json.Serialization.JsonPropertyName("error")] string Error,
    [property: System.Text.Json.Serialization.JsonPropertyName("error_description")] string ErrorDescription);
