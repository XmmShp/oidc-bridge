using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using OAuth2Bridge.Providers;

namespace OAuth2Bridge.Tests;

public sealed class DingTalkProviderTests
{
    [Fact]
    public async Task Token_TranslatesRequestAndNormalizesOpenApiResponse()
    {
        using var factory = DingTalkFactory(async request =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("https://api.dingtalk.com/v1.0/oauth2/userAccessToken", request.RequestUri!.ToString());
            Assert.Null(request.Headers.Authorization);
            Assert.Equal("application/json", request.Content!.Headers.ContentType!.MediaType);
            using var body = JsonDocument.Parse(await request.Content.ReadAsStringAsync());
            Assert.Equal("ding-app", body.RootElement.GetProperty("clientId").GetString());
            Assert.Equal("ding-secret", body.RootElement.GetProperty("clientSecret").GetString());
            Assert.Equal("ding-code", body.RootElement.GetProperty("code").GetString());
            Assert.Equal("authorization_code", body.RootElement.GetProperty("grantType").GetString());
            return Json("""{"accessToken":"ding-access","expireIn":7200,"refreshToken":"ding-refresh"}""");
        });
        using var client = factory.CreateClient();
        using var result = await client.PostAsync("/dingtalk/token", Form());
        result.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await result.Content.ReadAsStringAsync());
        Assert.Equal("ding-access", json.RootElement.GetProperty("access_token").GetString());
        Assert.Equal("Bearer", json.RootElement.GetProperty("token_type").GetString());
        Assert.Equal(7200, json.RootElement.GetProperty("expires_in").GetInt32());
        Assert.Equal("ding-refresh", json.RootElement.GetProperty("refresh_token").GetString());
        Assert.True(result.Headers.CacheControl!.NoStore);
    }

    [Fact]
    public async Task UserInfo_PreservesExistingClaimsAndRawDingTalkFields()
    {
        using var factory = DingTalkFactory(request =>
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal("https://api.dingtalk.com/v1.0/contact/users/me", request.RequestUri!.ToString());
            Assert.Equal("ding-access", Assert.Single(request.Headers.GetValues("x-acs-dingtalk-access-token")));
            Assert.Null(request.Headers.Authorization);
            return Task.FromResult(Json("""{"unionId":"union","nick":"nick","openId":"open","avatarUrl":"avatar","stateCode":"86","mobile":"123","loginEmail":"login@example.com","visitor":false,"extra":"preserved"}"""));
        });
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "ding-access");
        using var result = await client.GetAsync("/dingtalk/userinfo");
        result.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await result.Content.ReadAsStringAsync());
        var user = json.RootElement;
        Assert.Equal("union", user.GetProperty("sub").GetString());
        Assert.Equal("nick", user.GetProperty("name").GetString());
        Assert.Equal("login@example.com", user.GetProperty("email").GetString());
        Assert.Equal("open", user.GetProperty("openId").GetString());
        Assert.Equal("union", user.GetProperty("dingtalk").GetProperty("unionId").GetString());
        Assert.Equal("preserved", user.GetProperty("dingtalk").GetProperty("extra").GetString());
        Assert.Equal("avatar", user.GetProperty("picture").GetString());
        Assert.Equal("123", user.GetProperty("phone_number").GetString());
        Assert.False(user.GetProperty("visitor").GetBoolean());
    }

    [Fact]
    public async Task Token_MalformedBasicAuthDoesNotFallBackToBodyCredentials()
    {
        using var factory = new OAuthBridgeFactory();
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/dingtalk/token") { Content = Form() };
        request.Headers.TryAddWithoutValidation("Authorization", "Basic not-base64!");
        using var result = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
        Assert.Contains("Basic", result.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task Token_RejectsMultipleClientAuthenticationMethods()
    {
        using var factory = new OAuthBridgeFactory();
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/dingtalk/token") { Content = Form() };
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("app:secret")));
        using var result = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        using var json = JsonDocument.Parse(await result.Content.ReadAsStringAsync());
        Assert.Equal("invalid_request", json.RootElement.GetProperty("error").GetString());
    }

    private static FormUrlEncodedContent Form() => new(new Dictionary<string, string>
    {
        ["grant_type"] = "authorization_code", ["code"] = "ding-code",
        ["client_id"] = "ding-app", ["client_secret"] = "ding-secret"
    });

    [Theory]
    [InlineData(400, "{\"code\":\"InvalidCode\",\"message\":\"sensitive-upstream-data\"}", 400, "invalid_grant")]
    [InlineData(401, "sensitive-upstream-data", 400, "invalid_client")]
    [InlineData(200, "{\"code\":\"InvalidCode\",\"message\":\"sensitive-upstream-data\"}", 400, "invalid_grant")]
    [InlineData(429, "sensitive-upstream-data", 502, null)]
    [InlineData(503, "sensitive-upstream-data", 502, null)]
    [InlineData(200, "not-json", 502, null)]
    [InlineData(200, "[]", 502, null)]
    [InlineData(200, "{}", 502, null)]
    [InlineData(200, "{\"accessToken\":\"access\",\"expireIn\":0}", 502, null)]
    public async Task Token_HandlesUpstreamFailures(int status, string body, int expectedStatus, string? error)
    {
        using var factory = DingTalkFactory(_ => Task.FromResult(Json(body, status)));
        using var client = factory.CreateClient();
        using var result = await client.PostAsync("/dingtalk/token", Form());
        Assert.Equal(expectedStatus, (int)result.StatusCode);
        var content = await result.Content.ReadAsStringAsync();
        Assert.DoesNotContain("sensitive-upstream-data", content);
        if (error is not null)
        {
            using var json = JsonDocument.Parse(content);
            Assert.Equal(error, json.RootElement.GetProperty("error").GetString());
        }
    }

    [Theory]
    [InlineData(401, "{\"code\":\"InvalidToken\"}", 401)]
    [InlineData(200, "{\"code\":\"InvalidToken\"}", 401)]
    [InlineData(503, "unavailable", 502)]
    [InlineData(200, "{\"nick\":\"missing-subject\"}", 502)]
    public async Task UserInfo_HandlesUpstreamFailures(int status, string body, int expectedStatus)
    {
        using var factory = DingTalkFactory(_ => Task.FromResult(Json(body, status)));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "ding-access");
        using var result = await client.GetAsync("/dingtalk/userinfo");
        Assert.Equal(expectedStatus, (int)result.StatusCode);
        if (expectedStatus == 401) Assert.Contains("invalid_token", result.Headers.WwwAuthenticate.ToString());
    }

    private static WebApplicationFactory<Program> DingTalkFactory(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) =>
        new OAuthBridgeFactory().WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.AddHttpClient<DingTalkOAuthProvider>().ConfigurePrimaryHttpMessageHandler(() => new StubHandler(send))));

    private static HttpResponseMessage Json(string body, int status = 200) => new((HttpStatusCode)status)
    { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class StubHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request);
    }
}
