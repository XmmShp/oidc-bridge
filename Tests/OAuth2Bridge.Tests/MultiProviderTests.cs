using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OAuth2Bridge.Providers;

namespace OAuth2Bridge.Tests;

public sealed class MultiProviderTests
{
    [Theory]
    [InlineData("https://auth.example.com/subroute", "/subroute")]
    [InlineData("https://auth.example.com/subroute/", "/subroute")]
    [InlineData("https://auth.example.com/parent/subroute", "/parent/subroute")]
    public async Task BaseUrlPath_IsOnlyUsedForMetadataAndProxyMustStripPrefix(string baseUrl, string prefix)
    {
        using var factory = new OAuthBridgeFactory();
        using var configured = factory.WithBaseUrl(baseUrl);
        using var client = configured.CreateClient(new() { AllowAutoRedirect = false });
        foreach (var provider in new[] { "dingtalk", "feishu" })
        {
            using var discovery = await client.GetAsync($"/{provider}/.well-known/oauth-authorization-server");
            discovery.EnsureSuccessStatusCode();
            using var json = JsonDocument.Parse(await discovery.Content.ReadAsStringAsync());
            Assert.Equal($"https://auth.example.com{prefix}/{provider}", json.RootElement.GetProperty("issuer").GetString());
            Assert.Equal($"https://auth.example.com{prefix}/{provider}/token", json.RootElement.GetProperty("token_endpoint").GetString());
            using var authorization = await client.GetAsync($"/{provider}/authorize?response_type=code&client_id=app&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback");
            Assert.Equal(HttpStatusCode.Redirect, authorization.StatusCode);
            using var token = await client.PostAsync($"/{provider}/token", new FormUrlEncodedContent(new Dictionary<string, string>()));
            Assert.Equal(HttpStatusCode.BadRequest, token.StatusCode);
            using var userInfo = await client.GetAsync($"/{provider}/userinfo");
            Assert.Equal(HttpStatusCode.Unauthorized, userInfo.StatusCode);

            foreach (var endpoint in new[] { "authorize", "userinfo", ".well-known/oauth-authorization-server" })
            {
                using var prefixed = await client.GetAsync($"{prefix}/{provider}/{endpoint}");
                Assert.Equal(HttpStatusCode.NotFound, prefixed.StatusCode);
            }
            using var prefixedToken = await client.PostAsync($"{prefix}/{provider}/token", new FormUrlEncodedContent(new Dictionary<string, string>()));
            Assert.Equal(HttpStatusCode.NotFound, prefixedToken.StatusCode);
        }

        using var root = JsonDocument.Parse(await client.GetStringAsync("/"));
        foreach (var provider in root.RootElement.GetProperty("providers").EnumerateArray())
            Assert.StartsWith($"https://auth.example.com{prefix}/", provider.GetProperty("metadata").GetString());
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("/relative")]
    [InlineData("invalid")]
    [InlineData("ftp://auth.example.com")]
    [InlineData("https://auth.example.com/path?query=value")]
    [InlineData("https://auth.example.com/path#fragment")]
    [InlineData("https://user:password@auth.example.com")]
    public void InvalidBaseUrl_FailsAtStartup(string baseUrl)
    {
        using var factory = new OAuthBridgeFactory();
        using var configured = factory.WithBaseUrl(baseUrl);
        var error = Assert.Throws<OptionsValidationException>(() => configured.CreateClient());
        Assert.Contains("BaseUrl", error.Message);
    }

    [Theory]
    [InlineData("dingtalk")]
    [InlineData("feishu")]
    [InlineData("github")]
    [InlineData("gitee")]
    [InlineData("weibo")]
    [InlineData("qq")]
    [InlineData("wechat")]
    [InlineData("wechat-mp")]
    public async Task Discovery_IsIsolatedByProvider(string provider)
    {
        using var factory = new OAuthBridgeFactory();
        using var prefixed = factory.WithBaseUrl("https://auth.example.com/bridge");
        using var client = prefixed.CreateClient();
        using var result = await client.GetAsync($"/{provider}/.well-known/oauth-authorization-server");
        using var json = JsonDocument.Parse(await result.Content.ReadAsStringAsync());
        Assert.Equal($"https://auth.example.com/bridge/{provider}", json.RootElement.GetProperty("issuer").GetString());
        Assert.Equal($"https://auth.example.com/bridge/{provider}/token", json.RootElement.GetProperty("token_endpoint").GetString());
        using var canonical = await client.GetAsync($"/.well-known/oauth-authorization-server/{provider}");
        Assert.Equal(await result.Content.ReadAsStringAsync(), await canonical.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Root_ListsRegisteredProvidersAndNewServiceName()
    {
        using var factory = new OAuthBridgeFactory();
        using var client = factory.CreateClient();
        using var json = JsonDocument.Parse(await client.GetStringAsync("/"));
        Assert.Equal("oauth2-bridge", json.RootElement.GetProperty("service").GetString());
        var providers = json.RootElement.GetProperty("providers").EnumerateArray()
            .Select(provider => provider.GetProperty("name").GetString()).ToArray();
        Assert.Equal(new[] { "dingtalk", "feishu", "gitee", "github", "qq", "wechat", "wechat-mp", "weibo" }, providers.Order().ToArray());
        Assert.DoesNotContain("gitlab", providers);
        Assert.DoesNotContain("discord", providers);
        var native = json.RootElement.GetProperty("direct_providers").EnumerateArray().ToArray();
        Assert.Contains(native, p => p.GetProperty("name").GetString() == "gitlab" &&
            p.GetProperty("metadata").GetString() == "https://gitlab.com/.well-known/openid-configuration");
        Assert.Contains(native, p => p.GetProperty("name").GetString() == "discord");
    }

    [Theory]
    [InlineData("GET", "/authorize")]
    [InlineData("POST", "/token")]
    [InlineData("GET", "/userinfo")]
    [InlineData("GET", "/.well-known/oauth-authorization-server")]
    [InlineData("GET", "/.well-known/openid-configuration")]
    [InlineData("GET", "/dingtalk/.well-known/openid-configuration")]
    [InlineData("GET", "/feishu/.well-known/openid-configuration")]
    public async Task LegacyEndpoints_AreNotAvailable(string method, string path)
    {
        using var factory = new OAuthBridgeFactory();
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        using var result = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NotFound, result.StatusCode);
    }

    [Theory]
    [InlineData("/unknown/authorize")]
    [InlineData("/unknown/userinfo")]
    [InlineData("/unknown/.well-known/oauth-authorization-server")]
    [InlineData("/gitlab/authorize")]
    [InlineData("/discord/.well-known/oauth-authorization-server")]
    public async Task UnknownProvider_ReturnsNotFound(string path)
    {
        using var factory = new OAuthBridgeFactory();
        using var client = factory.CreateClient();
        using var result = await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.NotFound, result.StatusCode);
    }

    [Fact]
    public async Task FeishuAuthorization_ForwardsScopeStateRedirectAndPkce()
    {
        using var factory = new OAuthBridgeFactory();
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        var parameters = new Dictionary<string, string?>
        {
            ["response_type"] = "code", ["client_id"] = "cli-app", ["redirect_uri"] = "https://client.test/callback?x=1",
            ["scope"] = "contact:user.base:readonly offline_access", ["state"] = "a+b&c=中文",
            ["code_challenge"] = "challenge", ["code_challenge_method"] = "S256", ["prompt"] = "consent"
        };
        using var result = await client.GetAsync(QueryHelpers.AddQueryString("/feishu/authorize", parameters));
        Assert.Equal(HttpStatusCode.Redirect, result.StatusCode);
        Assert.Equal("accounts.feishu.cn", result.Headers.Location?.Host);
        var query = QueryHelpers.ParseQuery(result.Headers.Location!.Query);
        foreach (var parameter in parameters) Assert.Equal(parameter.Value, query[parameter.Key].ToString());
    }

    [Fact]
    public async Task DingTalk_RejectsPkceInsteadOfSilentlyDroppingIt()
    {
        using var factory = new OAuthBridgeFactory();
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        using var result = await client.GetAsync("/dingtalk/authorize?response_type=code&client_id=app&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&code_challenge=challenge");
        Assert.Equal("invalid_request", QueryHelpers.ParseQuery(result.Headers.Location!.Query)["error"]);
    }

    [Theory]
    [InlineData("dingtalk", "openid corpid", "openid corpid")]
    [InlineData("dingtalk", "", "openid")]
    [InlineData("feishu", "contact:user.base:readonly", "contact:user.base:readonly")]
    [InlineData("feishu", "", null)]
    public async Task Authorization_UsesRequestScopeOrProviderDefault(string provider, string scope, string? expectedScope)
    {
        using var factory = new OAuthBridgeFactory();
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        var url = QueryHelpers.AddQueryString($"/{provider}/authorize", new Dictionary<string, string?>
        {
            ["response_type"] = "code", ["client_id"] = "app", ["redirect_uri"] = "https://client.test/callback", ["scope"] = scope
        });
        using var result = await client.GetAsync(url);
        Assert.Equal(HttpStatusCode.Redirect, result.StatusCode);
        var query = QueryHelpers.ParseQuery(result.Headers.Location!.Query);
        if (expectedScope is null) Assert.False(query.ContainsKey("scope"));
        else Assert.Equal(expectedScope, query["scope"].ToString());
    }

    [Fact]
    public async Task FeishuToken_TranslatesBasicAuthAndForwardsRedirectAndVerifier()
    {
        JsonElement sent = default;
        using var factory = FeishuFactory(async request =>
        {
            Assert.Equal("https://accounts.feishu.cn/oauth/v3/token", request.RequestUri!.ToString());
            Assert.Null(request.Headers.Authorization);
            sent = JsonSerializer.Deserialize<JsonElement>(await request.Content!.ReadAsStringAsync());
            return Json("""{"code":0,"access_token":"access","expires_in":7200,"refresh_token":"refresh","scope":"contact:user.base:readonly","token_type":"Bearer"}""");
        });
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/feishu/token") { Content = TokenForm() };
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("cli-app:test-secret")));
        using var result = await client.SendAsync(request);
        result.EnsureSuccessStatusCode();
        Assert.Equal("cli-app", sent.GetProperty("client_id").GetString());
        Assert.Equal("test-secret", sent.GetProperty("client_secret").GetString());
        Assert.Equal("auth-code", sent.GetProperty("code").GetString());
        Assert.Equal("https://client.test/callback", sent.GetProperty("redirect_uri").GetString());
        Assert.Equal("verifier", sent.GetProperty("code_verifier").GetString());
        Assert.True(result.Headers.CacheControl!.NoStore);
        using var json = JsonDocument.Parse(await result.Content.ReadAsStringAsync());
        Assert.Equal("access", json.RootElement.GetProperty("access_token").GetString());
        Assert.Equal("refresh", json.RootElement.GetProperty("refresh_token").GetString());
        Assert.Equal(7200, json.RootElement.GetProperty("expires_in").GetInt32());
        Assert.Equal("contact:user.base:readonly", json.RootElement.GetProperty("scope").GetString());
    }

    [Theory]
    [InlineData("{\"code\":20003,\"error\":\"invalid_grant\",\"error_description\":\"sensitive-upstream-data\"}", 200, 400, "invalid_grant")]
    [InlineData("{\"code\":20002,\"error\":\"invalid_client\"}", 400, 400, "invalid_client")]
    [InlineData("{\"code\":20003,\"msg\":\"sensitive-upstream-data\"}", 200, 400, "invalid_grant")]
    [InlineData("not-json", 503, 502, null)]
    [InlineData("not-json", 200, 502, null)]
    [InlineData("{\"code\":0}", 200, 502, null)]
    [InlineData("[]", 200, 502, null)]
    [InlineData("{\"error\":\"server_error\"}", 200, 502, null)]
    public async Task FeishuToken_HandlesUpstreamFailures(string body, int upstreamStatus, int expectedStatus, string? error)
    {
        using var factory = FeishuFactory(_ => Task.FromResult(Json(body, upstreamStatus)));
        using var client = factory.CreateClient();
        using var result = await client.PostAsync("/feishu/token", TokenForm(true));
        Assert.Equal(expectedStatus, (int)result.StatusCode);
        var content = await result.Content.ReadAsStringAsync();
        Assert.DoesNotContain("sensitive-upstream-data", content);
        if (error is not null)
        {
            using var json = JsonDocument.Parse(content);
            Assert.Equal(error, json.RootElement.GetProperty("error").GetString());
        }
    }

    [Fact]
    public async Task FeishuUserInfo_NormalizesClaimsAndPreservesOriginalFields()
    {
        using var factory = FeishuFactory(request =>
        {
            Assert.Equal("/open-apis/authen/v1/user_info", request.RequestUri!.AbsolutePath);
            Assert.Equal("Bearer user-token", request.Headers.Authorization!.ToString());
            return Task.FromResult(Json("""{"code":0,"data":{"open_id":"open-1","union_id":"union-1","user_id":"user-1","name":"Test User","avatar_url":"https://example.com/a.png","enterprise_email":"user@example.com","mobile":"123","tenant_key":"tenant"}}"""));
        });
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "user-token");
        using var result = await client.GetAsync("/feishu/userinfo");
        result.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await result.Content.ReadAsStringAsync());
        var user = json.RootElement;
        Assert.Equal("open-1", user.GetProperty("sub").GetString());
        Assert.Equal("Test User", user.GetProperty("name").GetString());
        Assert.Equal("user@example.com", user.GetProperty("email").GetString());
        Assert.Equal("123", user.GetProperty("phone_number").GetString());
        Assert.Equal("tenant", user.GetProperty("feishu").GetProperty("tenant_key").GetString());
    }

    [Fact]
    public async Task FeishuUserInfo_InvalidTokenReturnsBearerChallenge()
    {
        using var factory = FeishuFactory(_ => Task.FromResult(Json("""{"code":99991663,"msg":"invalid token"}""")));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "expired");
        using var result = await client.GetAsync("/feishu/userinfo");
        Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
        Assert.Contains("invalid_token", result.Headers.WwwAuthenticate.ToString());
    }

    [Theory]
    [InlineData("Basic abc")]
    [InlineData("token-without-scheme")]
    public async Task UserInfo_RejectsNonBearerHeaders(string header)
    {
        using var factory = new OAuthBridgeFactory();
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", header);
        using var result = await client.GetAsync("/feishu/userinfo");
        Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
    }

    [Fact]
    public async Task Token_MalformedJsonReturnsOAuthError()
    {
        using var factory = new OAuthBridgeFactory();
        using var client = factory.CreateClient();
        using var result = await client.PostAsync("/feishu/token", new StringContent("{", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        using var json = JsonDocument.Parse(await result.Content.ReadAsStringAsync());
        Assert.Equal("invalid_request", json.RootElement.GetProperty("error").GetString());
    }

    private static WebApplicationFactory<Program> FeishuFactory(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) =>
        new OAuthBridgeFactory().WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.AddHttpClient<FeishuOAuthProvider>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(send))));

    private static FormUrlEncodedContent TokenForm(bool credentials = false)
    {
        var parameters = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["code"] = "auth-code",
            ["redirect_uri"] = "https://client.test/callback", ["code_verifier"] = "verifier"
        };
        if (credentials) { parameters["client_id"] = "app"; parameters["client_secret"] = "secret"; }
        return new(parameters);
    }

    private static HttpResponseMessage Json(string body, int status = 200) => new((HttpStatusCode)status)
    { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class StubHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request);
    }
}
