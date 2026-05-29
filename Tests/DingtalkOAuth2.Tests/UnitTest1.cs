using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;

namespace DingtalkOAuth2.Tests;

public sealed class OAuthEndpointsTests(OAuthBridgeFactory factory) : IClassFixture<OAuthBridgeFactory>
{
    [Fact]
    public async Task Discovery_ReturnsStandardOAuthMetadata()
    {
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/.well-known/oauth-authorization-server");

        response.EnsureSuccessStatusCode();
        using var body = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var root = body.RootElement;

        Assert.Equal("http://localhost", root.GetProperty("issuer").GetString());
        Assert.Equal("http://localhost/authorize", root.GetProperty("authorization_endpoint").GetString());
        Assert.Equal("http://localhost/token", root.GetProperty("token_endpoint").GetString());
        Assert.Equal("http://localhost/userinfo", root.GetProperty("userinfo_endpoint").GetString());
        Assert.Contains("authorization_code", ReadStringArray(root.GetProperty("grant_types_supported")));
        Assert.Contains("client_secret_basic", ReadStringArray(root.GetProperty("token_endpoint_auth_methods_supported")));
        Assert.DoesNotContain("none", ReadStringArray(root.GetProperty("token_endpoint_auth_methods_supported")));
        Assert.Contains("unionId", ReadStringArray(root.GetProperty("claims_supported")));
        Assert.Contains("openId", ReadStringArray(root.GetProperty("claims_supported")));
        Assert.Contains("loginEmail", ReadStringArray(root.GetProperty("claims_supported")));
    }

    [Fact]
    public async Task Authorize_RedirectsToDingTalkWithStandardParameters()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        var redirectUri = "https://keycloak.example.com/realms/demo/broker/dingtalk/endpoint";
        var requestUri = QueryHelpers.AddQueryString(
            "/authorize",
            new Dictionary<string, string?>
            {
                ["response_type"] = "code",
                ["client_id"] = "ding-app-key",
                ["redirect_uri"] = redirectUri,
                ["state"] = "state-123"
            });

        using var response = await client.GetAsync(requestUri);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location;
        Assert.NotNull(location);
        Assert.Equal("login.dingtalk.test", location.Host);
        Assert.Equal("/oauth2/auth", location.AbsolutePath);

        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("code", query["response_type"]);
        Assert.Equal("ding-app-key", query["client_id"]);
        Assert.Equal(redirectUri, query["redirect_uri"]);
        Assert.Equal("openid", query["scope"]);
        Assert.Equal("state-123", query["state"]);
    }

    [Fact]
    public async Task Authorize_ReturnsErrorForUnsupportedResponseType()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        var redirectUri = "https://keycloak.example.com/callback";
        var requestUri = QueryHelpers.AddQueryString(
            "/authorize",
            new Dictionary<string, string?>
            {
                ["response_type"] = "token",
                ["client_id"] = "ding-app-key",
                ["redirect_uri"] = redirectUri,
                ["state"] = "bad-flow"
            });

        using var response = await client.GetAsync(requestUri);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location;
        Assert.NotNull(location);
        Assert.Equal("unsupported_response_type", QueryHelpers.ParseQuery(location.Query)["error"]);
        Assert.Equal("bad-flow", QueryHelpers.ParseQuery(location.Query)["state"]);
    }

    [Fact]
    public async Task Token_RejectsUnsupportedGrantType()
    {
        using var client = factory.CreateClient();

        using var response = await client.PostAsync(
            "/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "ding-app-key",
                ["client_secret"] = "ding-app-secret"
            }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var body = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Equal("unsupported_grant_type", body.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Token_RequiresClientSecretBeforeCallingDingTalk()
    {
        using var client = factory.CreateClient();

        using var response = await client.PostAsync(
            "/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = "auth-code",
                ["client_id"] = "ding-app-key"
            }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var body = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Equal("invalid_client", body.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Token_AcceptsClientCredentialsFromBasicAuth()
    {
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = "",
                ["client_secret"] = ""
            })
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("ding-app-key:ding-app-secret")));

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var body = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Equal("invalid_request", body.RootElement.GetProperty("error").GetString());
        Assert.Equal("code is required.", body.RootElement.GetProperty("error_description").GetString());
    }

    [Fact]
    public async Task UserInfo_RequiresBearerToken()
    {
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/userinfo");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static string[] ReadStringArray(JsonElement array) =>
        array.EnumerateArray().Select(item => item.GetString() ?? string.Empty).ToArray();
}

public sealed class OAuthBridgeFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration(configuration =>
        {
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["OAuth2Bridge:AuthorizeEndpoint"] = "https://login.dingtalk.test/oauth2/auth",
                ["OAuth2Bridge:DingTalkScope"] = "openid"
            });
        });
    }
}
