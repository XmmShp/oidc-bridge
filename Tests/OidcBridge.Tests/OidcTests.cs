using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OidcBridge.Providers;

namespace OidcBridge.Tests;

public sealed class OidcTests
{
    private const string RedirectUri = "https://client.example/callback";
    private const string BaseUrl = "https://auth.example.com/subroute";
    private const string Verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    private const string TestSigningKey = "oidc-bridge integration test signing seed";

    [Theory]
    [InlineData("dingtalk")]
    [InlineData("feishu")]
    [InlineData("github")]
    [InlineData("gitee")]
    [InlineData("qq")]
    [InlineData("weibo")]
    public async Task Discovery_AndJwks_RespectConfiguredIssuerAndExposeOnlyPublicKey(string provider)
    {
        using var factory = new OidcFactory();
        using var client = Client(factory);
        client.DefaultRequestHeaders.Add("X-Forwarded-Host", "attacker.example");
        using var metadata = JsonDocument.Parse(await client.GetStringAsync($"/{provider}/.well-known/openid-configuration"));
        var issuer = $"{BaseUrl}/{provider}";
        var root = metadata.RootElement;
        Assert.Equal(issuer, root.GetProperty("issuer").GetString());
        Assert.Equal($"{issuer}/jwks", root.GetProperty("jwks_uri").GetString());
        Assert.Equal($"{issuer}/authorize", root.GetProperty("authorization_endpoint").GetString());
        Assert.Equal($"{issuer}/token", root.GetProperty("token_endpoint").GetString());
        Assert.Equal($"{issuer}/userinfo", root.GetProperty("userinfo_endpoint").GetString());
        Assert.Equal("RS256", root.GetProperty("id_token_signing_alg_values_supported")[0].GetString());
        Assert.Equal("S256", root.GetProperty("code_challenge_methods_supported")[0].GetString());
        using var jwks = JsonDocument.Parse(await client.GetStringAsync($"/{provider}/jwks"));
        var key = jwks.RootElement.GetProperty("keys")[0];
        Assert.Equal("RSA", key.GetProperty("kty").GetString());
        Assert.False(key.TryGetProperty("d", out _));
        Assert.False(key.TryGetProperty("p", out _));
        Assert.False(string.IsNullOrEmpty(key.GetProperty("kid").GetString()));
        using var prefixed = await client.GetAsync($"/subroute/{provider}/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.NotFound, prefixed.StatusCode);
    }

    [Theory]
    [InlineData("dingtalk")]
    [InlineData("feishu")]
    public async Task CodeFlow_WorksAcrossIndependentInstancesAndProducesVerifiableIdToken(string provider)
    {
        var backend = new Upstream();
        using var first = new OidcFactory(backend);
        using var second = new OidcFactory(backend);
        using var browser = Client(first);
        using var callbackServer = Client(second);
        using var tokenServer = Client(first);
        var authorization = await Begin(browser, provider);
        var upstream = QueryHelpers.ParseQuery(authorization.Location.Query);
        Assert.Equal($"{BaseUrl}/{provider}/callback", upstream["redirect_uri"]);
        Assert.DoesNotContain("profile", upstream.TryGetValue("scope", out var nativeScope) ? nativeScope.ToString() : "");
        Assert.NotEqual("client-state", upstream["state"].ToString());
        Assert.DoesNotContain("client-nonce", upstream["state"].ToString());
        Assert.Contains("secure", authorization.SetCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", authorization.SetCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"path=/subroute/{provider}/callback", authorization.SetCookie);
        if (provider == "feishu")
        {
            Assert.Equal("S256", upstream["code_challenge_method"]);
            Assert.NotEqual(Challenge(Verifier), upstream["code_challenge"].ToString());
        }
        var code = await Complete(callbackServer, provider, authorization, "native-code");
        Assert.DoesNotContain("native-code", code);
        using var response = await Redeem(tokenServer, provider, code);
        response.EnsureSuccessStatusCode();
        Assert.True(response.Headers.CacheControl!.NoStore);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var access = body.RootElement.GetProperty("access_token").GetString()!;
        Assert.NotEqual("native-access", access);
        Assert.DoesNotContain("native-access", access);
        Assert.False(body.RootElement.TryGetProperty("refresh_token", out _));
        Assert.Equal("openid profile email", body.RootElement.GetProperty("scope").GetString());
        var idToken = body.RootElement.GetProperty("id_token").GetString()!;
        using var jwks = JsonDocument.Parse(await callbackServer.GetStringAsync($"/{provider}/jwks"));
        var key = new JsonWebKey(jwks.RootElement.GetProperty("keys")[0].GetRawText());
        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(idToken, new TokenValidationParameters
        {
            ValidIssuer = $"{BaseUrl}/{provider}", ValidAudience = "app", IssuerSigningKey = key,
            ValidAlgorithms = ["RS256"], ClockSkew = TimeSpan.Zero
        });
        Assert.True(validation.IsValid, validation.Exception?.ToString());
        var jwt = (JsonWebToken)validation.SecurityToken;
        Assert.Equal(key.KeyId, jwt.Kid);
        Assert.Equal("subject-1", jwt.Subject);
        Assert.Equal("client-nonce", jwt.GetClaim("nonce").Value);
        Assert.Equal(WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(access))[..16]), jwt.GetClaim("at_hash").Value);
        Assert.True(jwt.TryGetClaim("iat", out _));
        Assert.True(jwt.TryGetClaim("exp", out _));
        Assert.Equal($"{BaseUrl}/{provider}/callback", backend.RedirectUri);
        if (provider == "feishu") Assert.Equal(upstream["code_challenge"], Challenge(backend.Verifier!));
        else Assert.Null(backend.Verifier);

        foreach (var method in new[] { HttpMethod.Get, HttpMethod.Post })
        {
            using var request = new HttpRequestMessage(method, $"/{provider}/userinfo");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
            using var result = await callbackServer.SendAsync(request);
            result.EnsureSuccessStatusCode();
            using var user = JsonDocument.Parse(await result.Content.ReadAsStringAsync());
            Assert.Equal(jwt.Subject, user.RootElement.GetProperty("sub").GetString());
            Assert.Equal("Test User", user.RootElement.GetProperty("name").GetString());
            Assert.Equal("user@example.com", user.RootElement.GetProperty("email").GetString());
            Assert.False(user.RootElement.TryGetProperty("phone_number", out _));
            Assert.False(user.RootElement.TryGetProperty(provider, out _));
        }
        // The test upstream, rather than either bridge instance, enforces one-time code redemption.
        using var replay = await Redeem(callbackServer, provider, code);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        using var error = JsonDocument.Parse(await replay.Content.ReadAsStringAsync());
        Assert.Equal("invalid_grant", error.RootElement.GetProperty("error").GetString());
    }

    [Theory]
    [InlineData("redirect_uri", "https://attacker.example/callback", false)]
    [InlineData("client_id", "unknown", false)]
    [InlineData("code_challenge_method", "plain", true)]
    [InlineData("code_challenge", "invalid", true)]
    [InlineData("response_type", "id_token", true)]
    [InlineData("response_mode", "form_post", true)]
    [InlineData("scope", "openid offline_access", true)]
    [InlineData("prompt", "none", true)]
    [InlineData("prompt", "login", true)]
    [InlineData("max_age", "0", true)]
    [InlineData("request_uri", "https://attacker.example/request", true)]
    public async Task Authorize_RejectsUnsupportedOrUnsafeRequests(string parameter, string value, bool redirectError)
    {
        using var factory = new OidcFactory();
        using var client = Client(factory);
        var parameters = Parameters();
        parameters[parameter] = value;
        using var response = await client.GetAsync(QueryHelpers.AddQueryString("/dingtalk/authorize", parameters));
        Assert.Equal(redirectError ? HttpStatusCode.Redirect : HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        if (redirectError)
        {
            Assert.Equal("client.example", response.Headers.Location!.Host);
            Assert.True(QueryHelpers.ParseQuery(response.Headers.Location.Query).ContainsKey("error"));
        }
    }

    [Fact]
    public async Task Callback_RequiresIntactStateAndCorrectBrowserCookie()
    {
        using var factory = new OidcFactory();
        using var client = Client(factory);
        var flow = await Begin(client, "dingtalk");
        var callback = CallbackUrl("dingtalk", flow, "native-code");
        using var missing = await client.GetAsync(callback);
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
        using var wrongRequest = new HttpRequestMessage(HttpMethod.Get, callback);
        wrongRequest.Headers.Add("Cookie", flow.Cookie.Split('=')[0] + "=wrong");
        using var wrong = await client.SendAsync(wrongRequest);
        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        var state = QueryHelpers.ParseQuery(flow.Location.Query)["state"].ToString();
        using var tamperedRequest = new HttpRequestMessage(HttpMethod.Get, QueryHelpers.AddQueryString("/dingtalk/callback",
            new Dictionary<string, string?> { ["state"] = state + "x", ["code"] = "native-code" }));
        tamperedRequest.Headers.Add("Cookie", flow.Cookie);
        using var tampered = await client.SendAsync(tamperedRequest);
        Assert.Equal(HttpStatusCode.BadRequest, tampered.StatusCode);
        using var duplicateRequest = new HttpRequestMessage(HttpMethod.Get, callback + "&code=another");
        duplicateRequest.Headers.Add("Cookie", flow.Cookie);
        using var duplicate = await client.SendAsync(duplicateRequest);
        Assert.Equal(HttpStatusCode.BadRequest, duplicate.StatusCode);
    }

    [Fact]
    public async Task Callback_PropagatesDenialWithOriginalClientState()
    {
        using var factory = new OidcFactory();
        using var client = Client(factory);
        var flow = await Begin(client, "dingtalk");
        var state = QueryHelpers.ParseQuery(flow.Location.Query)["state"].ToString();
        using var request = new HttpRequestMessage(HttpMethod.Get, QueryHelpers.AddQueryString("/dingtalk/callback",
            new Dictionary<string, string?> { ["state"] = state, ["error"] = "access_denied" }));
        request.Headers.Add("Cookie", flow.Cookie);
        using var response = await client.SendAsync(request);
        var query = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        Assert.Equal("access_denied", query["error"]);
        Assert.Equal("client-state", query["state"]);
        Assert.Contains("expires=Thu, 01 Jan 1970", response.Headers.GetValues("Set-Cookie").Single());
    }

    [Theory]
    [InlineData("code_verifier", "wrong")]
    [InlineData("redirect_uri", "https://attacker.example/callback")]
    [InlineData("client_id", "other-app")]
    public async Task Token_RejectsBindingFailuresBeforeUpstreamCall(string parameter, string value)
    {
        var backend = new Upstream();
        using var factory = new OidcFactory(backend);
        using var client = Client(factory);
        var code = await Complete(client, "dingtalk", await Begin(client, "dingtalk"), "native-code");
        using var bad = await Redeem(client, "dingtalk", code, parameter, value);
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        Assert.Equal(0, backend.TokenCalls);
        using var good = await Redeem(client, "dingtalk", code);
        good.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task Tokens_RejectTamperingCrossProviderCrossPurposeAndUnknownKeys()
    {
        using var factory = new OidcFactory();
        using var client = Client(factory);
        var flow = await Begin(client, "dingtalk");
        var code = await Complete(client, "dingtalk", flow, "native-code");
        using var tampered = await Redeem(client, "dingtalk", code + "x");
        Assert.Equal(HttpStatusCode.BadRequest, tampered.StatusCode);
        using var crossProvider = await Redeem(client, "feishu", code);
        Assert.Equal(HttpStatusCode.BadRequest, crossProvider.StatusCode);
        var state = QueryHelpers.ParseQuery(flow.Location.Query)["state"].ToString();
        using var wrongPurpose = await Redeem(client, "dingtalk", "oidc." + state);
        Assert.Equal(HttpStatusCode.BadRequest, wrongPurpose.StatusCode);
        using var otherFactory = new OidcFactory(key: CreateKey());
        using var otherClient = Client(otherFactory);
        using var otherKey = await Redeem(otherClient, "dingtalk", code);
        Assert.Equal(HttpStatusCode.BadRequest, otherKey.StatusCode);
        using var token = await Redeem(client, "dingtalk", code);
        token.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await token.Content.ReadAsStringAsync());
        var access = json.RootElement.GetProperty("access_token").GetString()!;
        foreach (var (provider, value) in new[] { ("feishu", access), ("dingtalk", access + "x"), ("dingtalk", code) })
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"/{provider}/userinfo");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", value);
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Contains("invalid_token", response.Headers.WwwAuthenticate.ToString());
        }
    }

    [Fact]
    public async Task StateCodesAndAccessTokens_ExpireWithoutServerStorage()
    {
        var time = new TestTime();
        using var factory = new OidcFactory(time: time);
        using var client = Client(factory);
        var expiredFlow = await Begin(client, "dingtalk");
        time.Advance(TimeSpan.FromMinutes(11));
        using var expiredRequest = new HttpRequestMessage(HttpMethod.Get, CallbackUrl("dingtalk", expiredFlow, "expired"));
        expiredRequest.Headers.Add("Cookie", expiredFlow.Cookie);
        using var stateError = await client.SendAsync(expiredRequest);
        Assert.Equal(HttpStatusCode.BadRequest, stateError.StatusCode);
        var code = await Complete(client, "dingtalk", await Begin(client, "dingtalk"), "expired-code");
        time.Advance(TimeSpan.FromMinutes(3));
        using var codeError = await Redeem(client, "dingtalk", code);
        Assert.Equal(HttpStatusCode.BadRequest, codeError.StatusCode);
        var validCode = await Complete(client, "dingtalk", await Begin(client, "dingtalk"), "valid-code");
        using var token = await Redeem(client, "dingtalk", validCode);
        token.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await token.Content.ReadAsStringAsync());
        time.Advance(TimeSpan.FromHours(2));
        using var info = new HttpRequestMessage(HttpMethod.Get, "/dingtalk/userinfo");
        info.Headers.Authorization = new AuthenticationHeaderValue("Bearer", json.RootElement.GetProperty("access_token").GetString());
        using var accessError = await client.SendAsync(info);
        Assert.Equal(HttpStatusCode.Unauthorized, accessError.StatusCode);
    }

    [Fact]
    public async Task OpenIdOnly_ExcludesProfileClaimsAndAcceptsBasicClientAuthentication()
    {
        using var factory = new OidcFactory();
        using var client = Client(factory);
        var code = await Complete(client, "dingtalk", await Begin(client, "dingtalk", "openid"), "native-code");
        using var request = new HttpRequestMessage(HttpMethod.Post, "/dingtalk/token")
        { Content = new FormUrlEncodedContent(TokenParameters(code).Where(pair => pair.Key is not ("client_id" or "client_secret"))) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("app:secret")));
        using var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var jwt = new JsonWebToken(json.RootElement.GetProperty("id_token").GetString());
        Assert.False(jwt.TryGetClaim("name", out _));
        Assert.False(jwt.TryGetClaim("email", out _));
        using var infoRequest = new HttpRequestMessage(HttpMethod.Get, "/dingtalk/userinfo");
        infoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", json.RootElement.GetProperty("access_token").GetString());
        using var infoResponse = await client.SendAsync(infoRequest);
        using var info = JsonDocument.Parse(await infoResponse.Content.ReadAsStringAsync());
        Assert.Single(info.RootElement.EnumerateObject());
    }

    [Fact]
    public async Task Token_RejectsJsonAndDuplicateParametersWithoutConsumingCode()
    {
        var backend = new Upstream();
        using var factory = new OidcFactory(backend);
        using var client = Client(factory);
        var code = await Complete(client, "dingtalk", await Begin(client, "dingtalk"), "native-code");
        using var jsonResponse = await client.PostAsync("/dingtalk/token", new StringContent(
            JsonSerializer.Serialize(TokenParameters(code)), Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, jsonResponse.StatusCode);
        var pairs = TokenParameters(code).ToList();
        pairs.Add(new KeyValuePair<string, string>("code_verifier", Verifier));
        using var duplicateResponse = await client.PostAsync("/dingtalk/token", new FormUrlEncodedContent(pairs));
        Assert.Equal(HttpStatusCode.BadRequest, duplicateResponse.StatusCode);
        Assert.Equal(0, backend.TokenCalls);
        using var valid = await Redeem(client, "dingtalk", code);
        valid.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task Token_UsesUpstreamToAuthenticateClientAndChallengesRejectedBasicCredentials()
    {
        using var factory = new OidcFactory();
        using var client = Client(factory);
        var code = await Complete(client, "dingtalk", await Begin(client, "dingtalk"), "native-code");
        using var request = new HttpRequestMessage(HttpMethod.Post, "/dingtalk/token")
        { Content = new FormUrlEncodedContent(TokenParameters(code).Where(pair => pair.Key is not ("client_id" or "client_secret"))) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("app:wrong-secret")));
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Basic", response.Headers.WwwAuthenticate.ToString());
        Assert.DoesNotContain("id_token", await response.Content.ReadAsStringAsync());
        using var valid = await Redeem(client, "dingtalk", code);
        valid.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task ConfidentialClient_CanOmitNonceAndPkce_AndPreferencesAreHints()
    {
        using var factory = new OidcFactory();
        using var client = Client(factory);
        var parameters = Parameters();
        parameters.Remove("nonce");
        parameters.Remove("code_challenge");
        parameters.Remove("code_challenge_method");
        parameters["display"] = "page";
        parameters["ui_locales"] = "zh-CN";
        parameters["claims_locales"] = "zh-CN";
        parameters["acr_values"] = "urn:example:preference";
        using var authorization = await client.GetAsync(QueryHelpers.AddQueryString("/dingtalk/authorize", parameters));
        Assert.Equal(HttpStatusCode.Redirect, authorization.StatusCode);
        var flow = new Authorization(authorization.Headers.Location!, authorization.Headers.GetValues("Set-Cookie").Single());
        var code = await Complete(client, "dingtalk", flow, "native-code");
        using var response = await Redeem(client, "dingtalk", code);
        response.EnsureSuccessStatusCode();
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(new JsonWebToken(body.RootElement.GetProperty("id_token").GetString()).TryGetClaim("nonce", out _));
    }

    [Theory]
    [InlineData("prompt", "login", "login_required")]
    [InlineData("prompt", "none", "login_required")]
    [InlineData("prompt", "none consent", "invalid_request")]
    [InlineData("prompt", "select_account", "account_selection_required")]
    [InlineData("max_age", "0", "login_required")]
    [InlineData("max_age", "3600", "login_required")]
    [InlineData("max_age", "-1", "invalid_request")]
    public async Task AuthenticationConstraints_AreNeverSilentlyIgnored(string parameter, string value, string error)
    {
        using var factory = new OidcFactory();
        using var client = Client(factory);
        var parameters = Parameters();
        parameters[parameter] = value;
        using var response = await client.GetAsync(QueryHelpers.AddQueryString("/dingtalk/authorize", parameters));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal(error, QueryHelpers.ParseQuery(response.Headers.Location!.Query)["error"]);
    }

    [Theory]
    [InlineData("", BaseUrl)]
    [InlineData("any signing seed", "http://public.example.com")]
    public void InvalidOidcConfiguration_FailsAtStartup(string key, string url)
    {
        using var factory = new OidcFactory(key: key, baseUrl: url);
        Assert.Throws<OptionsValidationException>(() => Client(factory));
    }

    private static HttpClient Client(WebApplicationFactory<Program> factory) => factory.CreateClient(new()
    { AllowAutoRedirect = false, HandleCookies = false, BaseAddress = new Uri("https://internal.example") });
    private static string CreateKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    private static string Challenge(string value) => WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(value)));
    private static Dictionary<string, string?> Parameters(string scope = "openid profile email") => new()
    {
        ["response_type"] = "code", ["client_id"] = "app", ["redirect_uri"] = RedirectUri,
        ["scope"] = scope, ["state"] = "client-state", ["nonce"] = "client-nonce",
        ["code_challenge"] = Challenge(Verifier), ["code_challenge_method"] = "S256"
    };
    private sealed record Authorization(Uri Location, string SetCookie)
    { public string Cookie => SetCookie.Split(';')[0]; }
    private static async Task<Authorization> Begin(HttpClient client, string provider, string scope = "openid profile email")
    {
        using var response = await client.GetAsync(QueryHelpers.AddQueryString($"/{provider}/authorize", Parameters(scope)));
        Assert.True(response.StatusCode == HttpStatusCode.Redirect, await response.Content.ReadAsStringAsync());
        return new Authorization(response.Headers.Location!, response.Headers.GetValues("Set-Cookie").Single());
    }
    private static string CallbackUrl(string provider, Authorization flow, string code) => QueryHelpers.AddQueryString($"/{provider}/callback",
        new Dictionary<string, string?> { ["state"] = QueryHelpers.ParseQuery(flow.Location.Query)["state"].ToString(), ["code"] = code });
    private static async Task<string> Complete(HttpClient client, string provider, Authorization flow, string upstreamCode)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, CallbackUrl(provider, flow, upstreamCode));
        request.Headers.Add("Cookie", flow.Cookie);
        using var response = await client.SendAsync(request);
        Assert.True(response.StatusCode == HttpStatusCode.Redirect, await response.Content.ReadAsStringAsync());
        var query = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        Assert.Equal("client-state", query["state"]);
        Assert.Equal($"{BaseUrl}/{provider}", query["iss"]);
        return query["code"].ToString();
    }
    private static Dictionary<string, string> TokenParameters(string code) => new()
    {
        ["grant_type"] = "authorization_code", ["code"] = code, ["client_id"] = "app", ["client_secret"] = "secret",
        ["redirect_uri"] = RedirectUri, ["code_verifier"] = Verifier
    };
    private static Task<HttpResponseMessage> Redeem(HttpClient client, string provider, string code, string? parameter = null, string? value = null)
    {
        var parameters = TokenParameters(code);
        if (parameter is not null) parameters[parameter] = value!;
        return client.PostAsync($"/{provider}/token", new FormUrlEncodedContent(parameters));
    }

    private sealed class OidcFactory(Upstream? backend = null, string? key = null, TestTime? time = null, string baseUrl = BaseUrl)
        : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            backend ??= new Upstream();
            builder.ConfigureAppConfiguration(config => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["BaseUrl"] = baseUrl, ["SigningKey"] = key ?? TestSigningKey,
                ["Clients:0:Provider"] = "dingtalk", ["Clients:0:ClientId"] = "app",
                ["Clients:0:RedirectUris:0"] = RedirectUri,
                ["Clients:1:Provider"] = "feishu", ["Clients:1:ClientId"] = "app",
                ["Clients:1:RedirectUris:0"] = RedirectUri
            }));
            builder.ConfigureServices(services =>
            {
                services.AddHttpClient<DingTalkOAuthProvider>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(backend.Send));
                services.AddHttpClient<FeishuOAuthProvider>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(backend.Send));
                if (time is not null) services.AddSingleton<TimeProvider>(time);
            });
        }
    }
    private sealed class TestTime : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan amount) => _now += amount;
    }
    private sealed class Upstream
    {
        private readonly ConcurrentDictionary<string, bool> _used = new();
        public int TokenCalls;
        public string? RedirectUri;
        public string? Verifier;
        public async Task<HttpResponseMessage> Send(HttpRequestMessage request)
        {
            if (request.Method == HttpMethod.Post)
            {
                Interlocked.Increment(ref TokenCalls);
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
                var feishu = request.RequestUri!.Host is "accounts.feishu.cn" or "open.feishu.cn";
                var code = body.RootElement.GetProperty("code").GetString()!;
                if (body.RootElement.GetProperty(feishu ? "client_secret" : "clientSecret").GetString() != "secret")
                    return Json("{\"error\":\"invalid_client\"}", 401);
                if (!_used.TryAdd(code, true)) return Json("{\"error\":\"invalid_grant\"}", 400);
                if (feishu)
                {
                    RedirectUri = body.RootElement.GetProperty("redirect_uri").GetString();
                    Verifier = body.RootElement.GetProperty("code_verifier").GetString();
                    return Json("""{"access_token":"native-access","expires_in":7200}""");
                }
                RedirectUri = $"{BaseUrl}/dingtalk/callback"; // DingTalk does not accept redirect_uri at its token endpoint.
                return Json("""{"accessToken":"native-access","expireIn":7200}""");
            }
            return request.RequestUri!.Host == "api.dingtalk.com"
                ? Json("""{"unionId":"subject-1","nick":"Test User","email":"user@example.com","mobile":"123"}""")
                : Json("""{"code":0,"data":{"open_id":"subject-1","name":"Test User","email":"user@example.com","mobile":"123"}}""");
        }
        private static HttpResponseMessage Json(string body, int status = 200) => new((HttpStatusCode)status)
        { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    }
    private sealed class StubHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request);
    }
}
