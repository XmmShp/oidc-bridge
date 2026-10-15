using System.Text.Json;
using OidcBridge.Providers;
using static OidcBridge.OAuthRequestHelpers;

namespace OidcBridge.Oidc;

internal static partial class OidcEndpoints
{
    private static IResult Authorize(HttpRequest request, HttpResponse response, OAuthProviderRegistry providers, OidcService oidc)
    {
        var provider = Resolve(request, providers);
        return provider is null ? Results.NotFound() : BeginAuthorization(request, response, providers, provider, oidc);
    }

    private static async Task<IResult> Token(HttpRequest request, HttpResponse response, OAuthProviderRegistry providers,
        OidcService oidc, CancellationToken ct)
    {
        NoStore(response);
        var provider = Resolve(request, providers);
        if (provider is null) return Results.NotFound();
        if (!request.HasFormContentType)
            return Results.BadRequest(new OAuthError("invalid_request", "Token requests require form encoding."));
        Dictionary<string, string> parameters;
        try { parameters = await ReadRequestParametersAsync(request, ct); }
        catch (Exception ex) when (ex is JsonException or InvalidDataException or BadHttpRequestException)
        { return Results.BadRequest(new OAuthError("invalid_request", "Malformed token request.")); }
        if (GetRequired(parameters, "grant_type") != "authorization_code")
            return Results.BadRequest(new OAuthError("unsupported_grant_type", "Only authorization_code grant is supported."));
        var code = GetRequired(parameters, "code");
        if (string.IsNullOrWhiteSpace(code)) return Results.BadRequest(new OAuthError("invalid_request", "code is required."));
        var clientId = GetClientId(request, parameters);
        var clientSecret = GetClientSecret(request, parameters);
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
        {
            var error = new OAuthError("invalid_client", "client_id and client_secret are required.");
            if (request.Headers.ContainsKey("Authorization"))
            {
                response.Headers.WWWAuthenticate = "Basic realm=\"oidc-bridge\"";
                return Results.Json(error, statusCode: StatusCodes.Status401Unauthorized);
            }
            return Results.BadRequest(error);
        }
        if (request.Headers.ContainsKey("Authorization") &&
            (!string.IsNullOrEmpty(GetOptional(parameters, "client_id")) || !string.IsNullOrEmpty(GetOptional(parameters, "client_secret"))))
            return Results.BadRequest(new OAuthError("invalid_request", "Use only one client authentication method."));
        if (!code.StartsWith(OidcService.TokenPrefix, StringComparison.Ordinal))
            return Results.BadRequest(new OAuthError("invalid_grant", "A bridge-issued authorization code is required."));
        try { return await RedeemCode(request, provider, providers, oidc, parameters, clientId, clientSecret, code, ct); }
        catch (OAuthProviderException ex)
        {
            if (ex.Error == "invalid_client" && request.Headers.ContainsKey("Authorization"))
            {
                response.Headers.WWWAuthenticate = "Basic realm=\"oidc-bridge\"";
                return Results.Json(new OAuthError(ex.Error, ex.Message), statusCode: StatusCodes.Status401Unauthorized);
            }
            return Results.BadRequest(new OAuthError(ex.Error == "invalid_token" ? "invalid_grant" : ex.Error, ex.Message));
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException || ex is OperationCanceledException && !ct.IsCancellationRequested)
        { return Results.Problem("Upstream token exchange failed.", statusCode: StatusCodes.Status502BadGateway); }
    }

    private static async Task<IResult> UserInfo(HttpRequest request, HttpResponse response, OAuthProviderRegistry providers,
        OidcService oidc, CancellationToken ct)
    {
        NoStore(response);
        var provider = Resolve(request, providers);
        if (provider is null) return Results.NotFound();
        var authorization = request.Headers.Authorization.ToString();
        if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(authorization[7..]))
        {
            response.Headers.WWWAuthenticate = "Bearer";
            return Results.Unauthorized();
        }
        var token = authorization[7..].Trim();
        if (!token.StartsWith(OidcService.TokenPrefix, StringComparison.Ordinal)) return InvalidToken(response);
        try { return await ReadUserInfo(token, response, providers, provider, oidc, ct); }
        catch (OAuthProviderException) { return InvalidToken(response); }
        catch (Exception ex) when (ex is HttpRequestException or JsonException || ex is OperationCanceledException && !ct.IsCancellationRequested)
        { return Results.Problem("Upstream userinfo request failed.", statusCode: StatusCodes.Status502BadGateway); }
    }
}
