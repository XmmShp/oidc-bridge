using System.Net;
using System.Text.Json;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace OidcBridge.Tests;

public sealed class EndpointTests
{
    [Fact]
    public async Task TokenFailureDiagnostics_DoNotLogCodesOrCredentials()
    {
        using var logs = new CapturingLogs();
        using var factory = new OidcBridgeFactory().WithWebHostBuilder(builder =>
            builder.ConfigureLogging(logging => logging.AddProvider(logs)));
        using var client = factory.CreateClient();
        using var response = await client.PostAsync("/dingtalk/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["client_id"] = "private-client",
            ["client_secret"] = "private-secret", ["code"] = "private-code"
        }));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var diagnostics = string.Join("\n", logs.Messages);
        Assert.Contains("A bridge-issued authorization code is required.", diagnostics);
        Assert.DoesNotContain("private-client", diagnostics);
        Assert.DoesNotContain("private-secret", diagnostics);
        Assert.DoesNotContain("private-code", diagnostics);
    }

    private sealed class CapturingLogs : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();
        public ILogger CreateLogger(string categoryName) => new CapturingLogger(Messages);
        public void Dispose() { }
        private sealed class CapturingLogger(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) => messages.Enqueue(formatter(state, exception));
        }
    }

    [Fact]
    public async Task Root_PresentsOidcDiscoveryAsPrimaryIntegration()
    {
        using var factory = new OidcBridgeFactory();
        using var client = factory.CreateClient();
        using var root = JsonDocument.Parse(await client.GetStringAsync("/"));
        Assert.Equal("oidc-bridge", root.RootElement.GetProperty("service").GetString());
        var providers = root.RootElement.GetProperty("providers").EnumerateArray().ToArray();
        Assert.Equal(new[] { "dingtalk", "feishu", "gitee", "github", "qq", "weibo" },
            providers.Select(provider => provider.GetProperty("name").GetString()).Order().ToArray());
        foreach (var provider in providers)
            Assert.EndsWith("/.well-known/openid-configuration", provider.GetProperty("metadata").GetString());
        Assert.Contains(root.RootElement.GetProperty("direct_providers").EnumerateArray(),
            provider => provider.GetProperty("name").GetString() == "gitlab");
    }

    [Theory]
    [InlineData("")]
    [InlineData("/relative")]
    [InlineData("ftp://auth.example.com")]
    [InlineData("https://auth.example.com/path?query=value")]
    [InlineData("https://auth.example.com/path#fragment")]
    [InlineData("https://user:password@auth.example.com")]
    [InlineData("http://public.example.com")]
    public void InvalidBaseUrl_FailsAtStartup(string baseUrl)
    {
        using var factory = new OidcBridgeFactory(baseUrl);
        Assert.Throws<OptionsValidationException>(() => factory.CreateClient());
    }

    [Fact]
    public void MissingSigningKey_FailsWithoutPrintingConfigurationSecret()
    {
        using var factory = new OidcBridgeFactory(signingKey: "");
        var error = Assert.Throws<OptionsValidationException>(() => factory.CreateClient());
        Assert.Contains("SigningKey", error.Message);
    }

    [Theory]
    [InlineData("GET", "/authorize")]
    [InlineData("POST", "/token")]
    [InlineData("GET", "/userinfo")]
    [InlineData("GET", "/.well-known/openid-configuration")]
    [InlineData("GET", "/unknown/.well-known/openid-configuration")]
    [InlineData("GET", "/unknown/jwks")]
    [InlineData("GET", "/unknown/callback")]
    [InlineData("GET", "/wechat/authorize")]
    [InlineData("GET", "/wechat-mp/authorize")]
    [InlineData("GET", "/gitlab/authorize")]
    public async Task MissingProvidersAndRemovedAdapters_Return404(string method, string path)
    {
        using var factory = new OidcBridgeFactory();
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task OAuthMetadataAliases_DescribeTheSameOidcFlow()
    {
        using var factory = new OidcBridgeFactory();
        using var client = factory.CreateClient();
        var oidc = await client.GetStringAsync("/dingtalk/.well-known/openid-configuration");
        Assert.Equal(oidc, await client.GetStringAsync("/dingtalk/.well-known/oauth-authorization-server"));
        Assert.Equal(oidc, await client.GetStringAsync("/.well-known/oauth-authorization-server/dingtalk"));
    }

    [Fact]
    public async Task OidcCannotBeBypassedUsingMissingScopeNativeCodeOrNativeToken()
    {
        using var factory = new OidcBridgeFactory();
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        using var authorize = await client.GetAsync("/dingtalk/authorize?response_type=code&client_id=app&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback");
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        Assert.Contains("error=invalid_scope", authorize.Headers.Location!.Query);
        using var token = await client.PostAsync("/dingtalk/token", new FormUrlEncodedContent(new Dictionary<string, string>
        { ["grant_type"] = "authorization_code", ["client_id"] = "app", ["client_secret"] = "secret", ["code"] = "native-code" }));
        Assert.Equal(HttpStatusCode.BadRequest, token.StatusCode);
        using var error = JsonDocument.Parse(await token.Content.ReadAsStringAsync());
        Assert.Equal("invalid_grant", error.RootElement.GetProperty("error").GetString());
        client.DefaultRequestHeaders.Authorization = new("Bearer", "native-token");
        using var userinfo = await client.GetAsync("/dingtalk/userinfo");
        Assert.Equal(HttpStatusCode.Unauthorized, userinfo.StatusCode);
    }
}

public sealed class OidcBridgeFactory(string baseUrl = "https://auth.example.com", string signingKey = "endpoint test signing seed")
    : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder) => builder.ConfigureAppConfiguration(configuration =>
        configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["BaseUrl"] = baseUrl, ["SigningKey"] = signingKey,
            ["Clients:0:Provider"] = "dingtalk", ["Clients:0:ClientId"] = "app",
            ["Clients:0:RedirectUris:0"] = "https://client.example/callback"
        }));
}
