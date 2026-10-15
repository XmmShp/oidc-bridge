using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OAuth2Bridge.Providers;

namespace OAuth2Bridge.Tests;

public sealed class PublicProviderTests
{
    public static TheoryData<string, string, string, string> Providers => new()
    {
        { "github", "https://github.com/login/oauth/authorize", "client_id", "read:user" },
        { "gitee", "https://gitee.com/oauth/authorize", "client_id", "user_info" },
        { "weibo", "https://api.weibo.com/oauth2/authorize", "client_id", "" },
        { "qq", "https://graph.qq.com/oauth2.0/authorize", "client_id", "get_user_info" },
        { "wechat", "https://open.weixin.qq.com/connect/qrconnect", "appid", "snsapi_login" },
        { "wechat-mp", "https://open.weixin.qq.com/connect/oauth2/authorize", "appid", "snsapi_userinfo" }
    };

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Authorize_MapsPlatformParameters(string provider, string endpoint, string clientKey, string scope)
    {
        using var factory = new OAuthBridgeFactory();
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        var url = QueryHelpers.AddQueryString($"/{provider}/authorize", new Dictionary<string, string?>
        {
            ["response_type"] = "code", ["client_id"] = "app-key", ["redirect_uri"] = "https://client.test/callback?x=1",
            ["state"] = "a+b&中文"
        });
        using var result = await client.GetAsync(url);
        Assert.Equal(HttpStatusCode.Redirect, result.StatusCode);
        var location = result.Headers.Location!;
        Assert.Equal(endpoint, location.GetLeftPart(UriPartial.Path));
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("app-key", query[clientKey]);
        Assert.Equal("https://client.test/callback?x=1", query["redirect_uri"]);
        Assert.Equal("a+b&中文", query["state"]);
        if (scope.Length > 0) Assert.Equal(scope, query["scope"]);
        else Assert.False(query.ContainsKey("scope"));
        if (provider.StartsWith("wechat")) Assert.Equal("#wechat_redirect", location.Fragment);
    }

    [Theory]
    [InlineData("gitee")]
    [InlineData("weibo")]
    [InlineData("qq")]
    [InlineData("wechat")]
    [InlineData("wechat-mp")]
    public async Task Authorize_RejectsUnimplementedPkce(string provider)
    {
        using var factory = new OAuthBridgeFactory();
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        using var result = await client.GetAsync($"/{provider}/authorize?response_type=code&client_id=app&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&state=s&code_challenge=challenge&code_challenge_method=S256");
        Assert.Equal("invalid_request", QueryHelpers.ParseQuery(result.Headers.Location!.Query)["error"]);
    }

    [Fact]
    public async Task GitHub_PreservesPkcePromptAndSpaceSeparatedScope()
    {
        using var factory = new OAuthBridgeFactory();
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        using var result = await client.GetAsync("/github/authorize?response_type=code&client_id=app&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&scope=read%3Auser%20user%3Aemail&code_challenge=challenge&code_challenge_method=S256&prompt=select_account");
        var query = QueryHelpers.ParseQuery(result.Headers.Location!.Query);
        Assert.Equal("challenge", query["code_challenge"]);
        Assert.Equal("S256", query["code_challenge_method"]);
        Assert.Equal("select_account", query["prompt"]);
        Assert.Equal("read:user user:email", query["scope"]);
    }

    [Theory]
    [InlineData("qq")]
    [InlineData("weibo")]
    public async Task Authorize_ConvertsStandardScopeSeparator(string provider)
    {
        using var factory = new OAuthBridgeFactory();
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        using var result = await client.GetAsync($"/{provider}/authorize?response_type=code&client_id=app&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&state=s&scope=first%20second");
        Assert.Equal("first,second", QueryHelpers.ParseQuery(result.Headers.Location!.Query)["scope"]);
    }

    [Theory]
    [InlineData("github", "github.com", "/login/oauth/access_token")]
    [InlineData("gitee", "gitee.com", "/oauth/token")]
    [InlineData("weibo", "api.weibo.com", "/oauth2/access_token")]
    public async Task Token_TranslatesBasicCredentialsToFormPost(string provider, string host, string path)
    {
        using var factory = Factory(provider, async (request, _) =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal(host, request.RequestUri!.Host);
            Assert.Equal(path, request.RequestUri.AbsolutePath);
            Assert.Null(request.Headers.Authorization);
            Assert.Equal("application/x-www-form-urlencoded", request.Content!.Headers.ContentType!.MediaType);
            Assert.Contains("application/json", request.Headers.Accept.ToString());
            Assert.NotEmpty(request.Headers.UserAgent);
            var form = QueryHelpers.ParseQuery(await request.Content.ReadAsStringAsync());
            Assert.Equal("client+id", form["client_id"]);
            Assert.Equal("client:secret", form["client_secret"]);
            Assert.Equal("one-time-code", form["code"]);
            Assert.Equal("https://client.test/callback", form["redirect_uri"]);
            if (provider == "github") Assert.Equal("verifier", form["code_verifier"]);
            return Json("""{"access_token":"access","expires_in":3600,"refresh_token":"refresh","scope":"one,two"}""");
        });
        using var client = factory.CreateClient();
        using var message = new HttpRequestMessage(HttpMethod.Post, $"/{provider}/token") { Content = TokenForm(false, provider == "github") };
        message.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("client%2Bid:client%3Asecret")));
        using var response = await client.SendAsync(message);
        response.EnsureSuccessStatusCode();
        Assert.True(response.Headers.CacheControl!.NoStore);
        using var data = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("access", data.RootElement.GetProperty("access_token").GetString());
        Assert.Equal("refresh", data.RootElement.GetProperty("refresh_token").GetString());
        Assert.Equal(3600, data.RootElement.GetProperty("expires_in").GetInt32());
        Assert.Equal(provider is "github" or "weibo" ? "one two" : "one,two", data.RootElement.GetProperty("scope").GetString());
    }

    [Fact]
    public async Task GitHub_DoesNotInventTokenLifetime()
    {
        using var factory = Factory("github", (_, _) => Task.FromResult(Json("""{"access_token":"access","scope":"read:user","token_type":"bearer"}""")));
        using var client = factory.CreateClient();
        using var result = await client.PostAsync("/github/token", TokenForm());
        result.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await result.Content.ReadAsStringAsync());
        Assert.False(json.RootElement.TryGetProperty("expires_in", out _));
        Assert.Equal("Bearer", json.RootElement.GetProperty("token_type").GetString());
    }

    [Theory]
    [InlineData("github", 200, "{\"error\":\"incorrect_client_credentials\",\"error_description\":\"private-data\"}", 400, "invalid_client")]
    [InlineData("github", 200, "{\"error\":\"bad_verification_code\"}", 400, "invalid_grant")]
    [InlineData("gitee", 400, "{\"error\":\"invalid_grant\"}", 400, "invalid_grant")]
    [InlineData("gitee", 401, "{\"error\":\"invalid_client\"}", 400, "invalid_client")]
    [InlineData("weibo", 200, "{\"error_code\":21325,\"error\":\"private-data\"}", 400, "invalid_grant")]
    [InlineData("qq", 200, "{\"error\":100020,\"error_description\":\"private-data\"}", 400, "invalid_grant")]
    [InlineData("wechat", 200, "{\"errcode\":40029,\"errmsg\":\"private-data\"}", 400, "invalid_grant")]
    [InlineData("github", 503, "private-data", 502, null)]
    [InlineData("gitee", 429, "private-data", 502, null)]
    [InlineData("github", 200, "not-json", 502, null)]
    [InlineData("weibo", 200, "[]", 502, null)]
    [InlineData("github", 200, "{}", 502, null)]
    [InlineData("github", 200, "{\"access_token\":\"access\",\"expires_in\":-1}", 502, null)]
    public async Task Token_MapsUpstreamFailuresWithoutLeakingDetails(string provider, int status, string body, int expectedStatus, string? error)
    {
        using var factory = Factory(provider, (_, _) => Task.FromResult(Json(body, status)));
        using var client = factory.CreateClient();
        using var response = await client.PostAsync($"/{provider}/token", TokenForm());
        Assert.Equal(expectedStatus, (int)response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("private-data", content);
        if (error is not null)
        {
            using var json = JsonDocument.Parse(content);
            Assert.Equal(error, json.RootElement.GetProperty("error").GetString());
        }
    }

    [Theory]
    [InlineData("github", "api.github.com", "/user", "{\"id\":9223372036854775807,\"login\":\"octocat\",\"name\":null,\"avatar_url\":\"https://example.com/a\",\"email\":null}", "9223372036854775807", "octocat")]
    [InlineData("gitee", "gitee.com", "/api/v5/user", "{\"id\":123,\"login\":\"gitee-user\",\"name\":\"Gitee User\",\"email\":\"user@example.com\"}", "123", "Gitee User")]
    public async Task UserInfo_UsesStableIdsAndNormalizesProfile(string provider, string host, string path, string body, string subject, string name)
    {
        using var factory = Factory(provider, (request, _) =>
        {
            Assert.Equal(host, request.RequestUri!.Host);
            Assert.Equal(path, request.RequestUri.AbsolutePath);
            if (provider == "gitee") Assert.Equal("access", QueryHelpers.ParseQuery(request.RequestUri.Query)["access_token"]);
            else Assert.Equal("Bearer access", request.Headers.Authorization!.ToString());
            return Task.FromResult(Json(body));
        });
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "access");
        using var result = await client.GetAsync($"/{provider}/userinfo");
        result.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await result.Content.ReadAsStringAsync());
        Assert.Equal(subject, json.RootElement.GetProperty("sub").GetString());
        Assert.Equal(name, json.RootElement.GetProperty("name").GetString());
        Assert.True(json.RootElement.TryGetProperty(provider, out _));
    }

    [Theory]
    [InlineData("github")]
    [InlineData("gitee")]
    [InlineData("weibo")]
    [InlineData("qq")]
    public async Task UserInfo_InvalidTokensReturnBearerChallenge(string provider)
    {
        using var factory = Factory(provider, (_, _) => Task.FromResult(Json("{\"error\":\"invalid_token\"}", 401)));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "expired");
        using var result = await client.GetAsync($"/{provider}/userinfo");
        Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
        Assert.Contains("invalid_token", result.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task Qq_UsesJsonFormatAndDerivesAppAndOpenIdFromToken()
    {
        var calls = 0;
        using var factory = Factory("qq", (request, _) =>
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            var query = QueryHelpers.ParseQuery(request.RequestUri!.Query);
            calls++;
            return Task.FromResult(request.RequestUri.AbsolutePath switch
            {
                "/oauth2.0/token" => QqToken(query),
                "/oauth2.0/me" => QqMe(query),
                "/user/get_user_info" => QqUser(query),
                _ => throw new InvalidOperationException("Unexpected endpoint.")
            });
        });
        using var client = factory.CreateClient();
        using var result = await client.PostAsync("/qq/token", TokenForm());
        result.EnsureSuccessStatusCode();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "qq-access");
        using var user = await client.GetAsync("/qq/userinfo");
        user.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await user.Content.ReadAsStringAsync());
        Assert.Equal("qq-open", json.RootElement.GetProperty("sub").GetString());
        Assert.Equal("QQ User", json.RootElement.GetProperty("name").GetString());
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task Weibo_QueriesTokenOwnerBeforeFetchingUser()
    {
        var calls = 0;
        using var factory = Factory("weibo", async (request, _) =>
        {
            calls++;
            if (calls == 1)
            {
                Assert.Equal(HttpMethod.Post, request.Method);
                Assert.Equal("/oauth2/get_token_info", request.RequestUri!.AbsolutePath);
                Assert.Equal("weibo-access", QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync())["access_token"]);
                return Json("{\"uid\":123456789012345678}");
            }
            var query = QueryHelpers.ParseQuery(request.RequestUri!.Query);
            Assert.Equal("123456789012345678", query["uid"]);
            Assert.Equal("weibo-access", query["access_token"]);
            return Json("""{"idstr":"123456789012345678","screen_name":"Weibo User","avatar_hd":"https://example.com/avatar"}""");
        });
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "weibo-access");
        using var result = await client.GetAsync("/weibo/userinfo");
        result.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await result.Content.ReadAsStringAsync());
        Assert.Equal("123456789012345678", json.RootElement.GetProperty("sub").GetString());
        Assert.Equal(2, calls);
    }

    private static HttpResponseMessage QqToken(Dictionary<string, Microsoft.Extensions.Primitives.StringValues> query)
    {
        Assert.Equal("json", query["fmt"]);
        Assert.Equal("app", query["client_id"]);
        Assert.Equal("secret", query["client_secret"]);
        Assert.Equal("https://client.test/callback", query["redirect_uri"]);
        return Json("""{"access_token":"qq-access","expires_in":7200,"refresh_token":"refresh"}""");
    }

    private static HttpResponseMessage QqMe(Dictionary<string, Microsoft.Extensions.Primitives.StringValues> query)
    {
        Assert.Equal("json", query["fmt"]);
        Assert.Equal("qq-access", query["access_token"]);
        return Json("""{"client_id":"app","openid":"qq-open"}""");
    }

    private static HttpResponseMessage QqUser(Dictionary<string, Microsoft.Extensions.Primitives.StringValues> query)
    {
        Assert.Equal("app", query["oauth_consumer_key"]);
        Assert.Equal("qq-open", query["openid"]);
        return Json("""{"ret":0,"nickname":"QQ User","figureurl_qq_2":"https://example.com/avatar"}""");
    }

    internal static WebApplicationFactory<Program> Factory(string provider, Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send, TimeProvider? time = null) =>
        new OAuthBridgeFactory().WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IDataProtectionProvider>();
            services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
            if (time is not null)
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton(time);
            }
            switch (provider)
            {
                case "github": services.AddHttpClient<GitHubOAuthProvider>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(send)); break;
                case "gitee": services.AddHttpClient<GiteeOAuthProvider>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(send)); break;
                case "weibo": services.AddHttpClient<WeiboOAuthProvider>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(send)); break;
                case "qq": services.AddHttpClient<QqOAuthProvider>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(send)); break;
                case "wechat": services.AddHttpClient<WeChatOAuthProvider>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(send)); break;
                case "wechat-mp": services.AddHttpClient<WeChatOfficialAccountOAuthProvider>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(send)); break;
                default: throw new ArgumentOutOfRangeException(nameof(provider));
            }
        }));

    internal static FormUrlEncodedContent TokenForm(bool credentials = true, bool pkce = false)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["code"] = "one-time-code", ["redirect_uri"] = "https://client.test/callback"
        };
        if (credentials) { form["client_id"] = "app"; form["client_secret"] = "secret"; }
        if (pkce) form["code_verifier"] = "verifier";
        return new(form);
    }

    internal static HttpResponseMessage Json(string body, int status = 200) => new((HttpStatusCode)status)
    { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
    }
}
