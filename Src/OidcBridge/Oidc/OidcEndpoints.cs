using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using OidcBridge.Providers;
using static OidcBridge.OAuthRequestHelpers;

namespace OidcBridge.Oidc;

internal static partial class OidcEndpoints
{
    public static void MapOidcEndpoints(this WebApplication app)
    {
        app.MapGet("/{provider}/.well-known/openid-configuration", Metadata);
        app.MapGet("/{provider}/jwks", (HttpRequest request, OAuthProviderRegistry providers, OidcService oidc) =>
            Resolve(request, providers) is not null ? Results.Ok(oidc.Jwks()) : Results.NotFound());
        app.MapGet("/{provider}/callback", Callback);
        app.MapGet("/{provider}/authorize", Authorize);
        app.MapPost("/{provider}/token", Token);
        app.MapGet("/{provider}/userinfo", UserInfo);
        app.MapPost("/{provider}/userinfo", UserInfo);
        app.MapGet("/{provider}/.well-known/oauth-authorization-server", Metadata);
        app.MapGet("/.well-known/oauth-authorization-server/{provider}", Metadata);
    }

    public static string Issuer(OAuthProviderRegistry providers, IOAuthProvider provider) =>
        $"{ResolveBaseUrl(providers.Options)}/{provider.Name}";

    private static IOAuthProvider? Resolve(HttpRequest request, OAuthProviderRegistry providers) =>
        providers.Find(request.RouteValues["provider"]?.ToString());

    private static IResult Metadata(HttpRequest request, OAuthProviderRegistry providers, OidcService oidc)
    {
        var provider = Resolve(request, providers);
        if (provider is null) return Results.NotFound();
        var issuer = Issuer(providers, provider);
        return Results.Ok(new
        {
            issuer, authorization_endpoint = $"{issuer}/authorize", token_endpoint = $"{issuer}/token",
            userinfo_endpoint = $"{issuer}/userinfo", jwks_uri = $"{issuer}/jwks",
            response_types_supported = new[] { "code" }, response_modes_supported = new[] { "query" },
            grant_types_supported = new[] { "authorization_code" }, subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "RS256" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" },
            code_challenge_methods_supported = new[] { "S256" }, scopes_supported = OidcService.Scopes,
            claims_supported = new[] { "iss", "sub", "aud", "exp", "iat", "nonce", "at_hash" }
                .Concat(provider.Claims.Where(claim => claim is "name" or "picture" or "email" or "phone_number" or "preferred_username")).Distinct(),
            claims_parameter_supported = false, request_parameter_supported = false, request_uri_parameter_supported = false,
            authorization_response_iss_parameter_supported = true
        });
    }

    private static IResult BeginAuthorization(HttpRequest request, HttpResponse response, OAuthProviderRegistry providers,
        IOAuthProvider provider, OidcService oidc)
    {
        NoStore(response);
        var query = request.Query;
        var client = oidc.FindClient(provider.Name, query["client_id"].ToString());
        var redirect = query["redirect_uri"].ToString();
        // Never send errors to an unregistered URI, including errors in response_type or scope.
        if (client is null || !client.RedirectUris.Contains(redirect))
            return Results.BadRequest(new OAuthError("invalid_request", "Unknown client or unregistered redirect_uri."));
        var state = query["state"].ToString();
        IResult Error(string error, string description) => AuthorizationError(redirect, state, error, description);
        if (query.Any(parameter => parameter.Value.Count != 1) || query.Any(parameter => parameter.Value.ToString().Length > 2048))
            return Error("invalid_request", "Duplicate or oversized authorization parameters.");
        if (query["response_type"] != "code") return Error("unsupported_response_type", "Only response_type=code is supported.");
        if (query["response_mode"].ToString() is not ("" or "query")) return Error("invalid_request", "Only response_mode=query is supported.");
        var scopes = query["scope"].ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct().ToArray();
        if (!scopes.Contains("openid") || scopes.Except(OidcService.Scopes).Any())
            return Error("invalid_scope", "Supported OIDC scopes are openid, profile, email, and phone.");
        if (query.ContainsKey("request")) return Error("request_not_supported", "Request objects are not supported.");
        if (query.ContainsKey("request_uri")) return Error("request_uri_not_supported", "Request objects are not supported.");
        if (query.ContainsKey("registration")) return Error("registration_not_supported", "Dynamic registration is not supported.");
        if (query.ContainsKey("claims")) return Error("invalid_request", "The claims request parameter is not supported.");
        if (query.ContainsKey("max_age"))
        {
            if (!long.TryParse(query["max_age"], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out _))
                return Error("invalid_request", "max_age must be a non-negative integer.");
            // Native OAuth responses do not attest the age of the user's platform authentication.
            return Error("login_required", "The platform cannot attest the requested authentication age.");
        }
        var prompt = query["prompt"].ToString();
        if (prompt == "none") return Error("login_required", "The bridge has no login session for silent authentication.");
        var prompts = prompt.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (prompts.Any(value => value is not ("none" or "login" or "consent" or "select_account")) ||
            prompts.Contains("none") && prompts.Length > 1)
            return Error("invalid_request", "Invalid prompt parameter.");
        if (prompts.Contains("login")) return Error("login_required", "The platform cannot guarantee forced reauthentication.");
        if (prompts.Contains("select_account")) return Error("account_selection_required", "The platform cannot guarantee account selection.");
        if (prompts.Contains("consent") && provider.Name is not ("dingtalk" or "feishu"))
            return Error("consent_required", "The platform cannot guarantee a fresh consent screen.");
        var challenge = query["code_challenge"].ToString();
        var method = query["code_challenge_method"].ToString();
        if (challenge.Length > 0 ? method != "S256" || !IsBase64Url(challenge, 43) : method.Length > 0)
            return Error("invalid_request", "PKCE requires a valid S256 challenge and code_challenge_method=S256.");
        var issuer = Issuer(providers, provider);
        var correlation = RandomToken();
        var transaction = new OidcTransaction(client.ClientId, redirect, state, string.Join(' ', scopes),
            query["nonce"].ToString(), challenge, RandomToken(), Hash(correlation),
            provider.CodeChallengeMethods.Contains("S256") ? RandomToken() : string.Empty);
        try
        {
            var url = provider.BuildAuthorizationUrl(new AuthorizationRequest(client.ClientId, $"{issuer}/callback",
                oidc.Seal(issuer, "state", transaction, TimeSpan.FromMinutes(10)), client.UpstreamScope,
                transaction.UpstreamVerifier.Length > 0 ? Hash(transaction.UpstreamVerifier) : string.Empty,
                transaction.UpstreamVerifier.Length > 0 ? "S256" : string.Empty, prompt));
            if (url.Length > 8000) return Error("invalid_request", "Authorization parameters exceed the supported URL size.");
            response.Cookies.Append(CookieName(issuer, transaction), correlation, CookieOptions(issuer, TimeSpan.FromMinutes(10)));
            return Results.Redirect(url);
        }
        catch (OAuthProviderException ex) { return Error(ex.Error, ex.Message); }
    }

    private static async Task<IResult> Callback(HttpRequest request, HttpResponse response, OAuthProviderRegistry providers, OidcService oidc)
    {
        NoStore(response);
        var provider = Resolve(request, providers);
        if (provider is null) return Results.NotFound();
        var issuer = Issuer(providers, provider);
        if (request.Query.Any(parameter => parameter.Value.Count != 1))
            return Results.BadRequest(new OAuthError("invalid_request", "Duplicate callback parameters."));
        var transaction = await oidc.UnsealAsync<OidcTransaction>(issuer, "state", request.Query["state"].ToString());
        if (transaction is null || oidc.FindClient(provider.Name, transaction.ClientId) is not { } client ||
            !client.RedirectUris.Contains(transaction.RedirectUri))
            return Results.BadRequest(new OAuthError("invalid_request", "Invalid or expired authorization state."));
        var cookieName = CookieName(issuer, transaction);
        if (!request.Cookies.TryGetValue(cookieName, out var correlation) || !FixedEquals(Hash(correlation), transaction.CorrelationHash))
            return Results.BadRequest(new OAuthError("invalid_request", "Missing or invalid browser correlation."));
        response.Cookies.Delete(cookieName, CookieOptions(issuer, null));
        var upstreamCode = FirstNonEmpty(request.Query["code"], request.Query["authCode"], request.Query["auth_code"]);
        var upstreamError = request.Query["error"].ToString();
        if (!string.IsNullOrEmpty(upstreamError) || string.IsNullOrWhiteSpace(upstreamCode))
            return AuthorizationError(transaction.RedirectUri, transaction.State,
                upstreamError == "access_denied" ? "access_denied" : "server_error", "The platform did not complete authorization.");
        var code = OidcService.TokenPrefix + oidc.Seal(issuer, "code", new OidcCode(transaction, upstreamCode), TimeSpan.FromMinutes(2));
        return Results.Redirect(QueryHelpers.AddQueryString(transaction.RedirectUri, new Dictionary<string, string?>
        { ["code"] = code, ["state"] = transaction.State, ["iss"] = issuer }));
    }

    private static async Task<IResult> RedeemCode(HttpRequest request, IOAuthProvider provider, OAuthProviderRegistry providers,
        OidcService oidc, Dictionary<string, string> parameters, string clientId, string clientSecret, string code, CancellationToken ct)
    {
        if (!request.HasFormContentType || GetOptional(parameters, "code") != code)
            return Results.BadRequest(new OAuthError("invalid_request", "OIDC token requests require form encoding and a code parameter."));
        var form = await request.ReadFormAsync(ct);
        if (form.Any(parameter => parameter.Value.Count != 1))
            return Results.BadRequest(new OAuthError("invalid_request", "Duplicate token parameters."));
        var issuer = Issuer(providers, provider);
        var envelope = await oidc.UnsealAsync<OidcCode>(issuer, "code", code[OidcService.TokenPrefix.Length..]);
        if (envelope is null || envelope.Transaction.ClientId != clientId ||
            GetOptional(parameters, "redirect_uri") != envelope.Transaction.RedirectUri ||
            oidc.FindClient(provider.Name, clientId) is not { } client ||
            !client.RedirectUris.Contains(envelope.Transaction.RedirectUri))
            return Results.BadRequest(new OAuthError("invalid_grant", "Invalid or expired authorization code, client, or redirect_uri."));
        var transaction = envelope.Transaction;
        var verifier = GetOptional(parameters, "code_verifier");
        if (transaction.CodeChallenge.Length > 0 && (!ValidVerifier(verifier) || !FixedEquals(Hash(verifier), transaction.CodeChallenge)))
            return Results.BadRequest(new OAuthError("invalid_grant", "PKCE verification failed."));
        // Redeem only here: upstream enforces one-time use, including across independent bridge instances.
        var native = await provider.ExchangeAuthorizationCodeAsync(new TokenRequest(clientId, clientSecret,
            envelope.UpstreamCode, $"{issuer}/callback", transaction.UpstreamVerifier), ct);
        var user = JsonSerializer.SerializeToElement(await provider.GetUserInfoAsync(native.AccessToken, ct));
        if (!user.TryGetProperty("sub", out var sub) || sub.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(sub.GetString()))
            throw new JsonException("Missing upstream subject.");
        var subject = sub.GetString()!;
        var lifetime = Math.Min(native.ExpiresIn ?? 3600, 3600);
        var access = OidcService.TokenPrefix + oidc.Seal(issuer, "access",
            new OidcAccess(clientId, native.AccessToken, subject, transaction.Scope), TimeSpan.FromSeconds(lifetime));
        return Results.Ok(new
        {
            access_token = access, token_type = "Bearer", expires_in = lifetime, scope = transaction.Scope,
            id_token = oidc.CreateIdToken(issuer, clientId, subject, transaction.Nonce, access, OidcService.FilterClaims(user, transaction.Scope))
        });
    }

    private static async Task<IResult> ReadUserInfo(string token, HttpResponse response, OAuthProviderRegistry providers,
        IOAuthProvider provider, OidcService oidc, CancellationToken ct)
    {
        var access = await oidc.UnsealAsync<OidcAccess>(Issuer(providers, provider), "access", token[OidcService.TokenPrefix.Length..]);
        if (access is null || oidc.FindClient(provider.Name, access.ClientId) is null) return InvalidToken(response);
        var user = JsonSerializer.SerializeToElement(await provider.GetUserInfoAsync(access.UpstreamToken, ct));
        if (!user.TryGetProperty("sub", out var sub) || sub.GetString() != access.Subject) return InvalidToken(response);
        return Results.Ok(OidcService.FilterClaims(user, access.Scope));
    }

    private static IResult InvalidToken(HttpResponse response)
    {
        response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";
        return Results.Json(new OAuthError("invalid_token", "Invalid or expired access token."), statusCode: 401);
    }

    private static void NoStore(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";
        response.Headers["Referrer-Policy"] = "no-referrer";
    }

    private static string CookieName(string issuer, OidcTransaction transaction) =>
        $"{(new Uri(issuer).Scheme == "https" ? "__Secure-" : string.Empty)}oidc-bridge.{new Uri(issuer).Segments.Last().TrimEnd('/')}.{transaction.CorrelationId}";
    private static CookieOptions CookieOptions(string issuer, TimeSpan? lifetime) => new()
    {
        HttpOnly = true, Secure = new Uri(issuer).Scheme == "https", SameSite = SameSiteMode.Lax,
        Path = new Uri($"{issuer}/callback").AbsolutePath, MaxAge = lifetime, IsEssential = true
    };
    private static string RandomToken() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    private static string Hash(string value) => WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(value)));
    private static bool FixedEquals(string left, string right) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(left), Encoding.UTF8.GetBytes(right));
    private static bool IsBase64Url(string value, int length) => value.Length == length &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
    private static bool ValidVerifier(string value) => value.Length is >= 43 and <= 128 &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or '~');
}
