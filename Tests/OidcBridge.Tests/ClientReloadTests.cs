using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OidcBridge.Oidc;
using OidcBridge.Providers;

namespace OidcBridge.Tests;

public sealed class ClientReloadTests
{
    private const string Redirect = "https://client.example/callback";

    [Fact]
    public void Registry_AddsUpdatesAndRemovesClientsAtomically()
    {
        var provider = new MutableConfiguration();
        using var configuration = new ConfigurationManager();
        configuration.Sources.Add(new MutableSource(provider));
        using var registry = new OidcClientRegistry(configuration, NullLogger<OidcClientRegistry>.Instance);
        Assert.Null(registry.Find("dingtalk", "app"));
        provider.Replace(Entry("app", Redirect));
        var original = registry.Find("DINGTALK", "app")!;
        Assert.Contains(Redirect, (IReadOnlySet<string>)original.RedirectUris);
        provider.Replace(Entry("app", "https://other.example/callback", "new-native-scope"));
        Assert.DoesNotContain(Redirect, (IReadOnlySet<string>)registry.Find("dingtalk", "app")!.RedirectUris);
        Assert.Equal("new-native-scope", registry.Find("dingtalk", "app")!.UpstreamScope);
        Assert.Contains(Redirect, (IReadOnlySet<string>)original.RedirectUris); // Older readers hold a coherent immutable snapshot.
        provider.Replace([]);
        Assert.Null(registry.Find("dingtalk", "app"));
    }

    [Theory]
    [InlineData("http://public.example/callback")]
    [InlineData("https://client.example/callback#fragment")]
    [InlineData("https://user:password@client.example/callback")]
    [InlineData("/relative")]
    [InlineData("")]
    public void InvalidUpdate_KeepsPreviousConfigAndLaterValidUpdateRecovers(string badRedirect)
    {
        var provider = new MutableConfiguration();
        provider.Replace(Entry("app", Redirect));
        using var configuration = new ConfigurationManager();
        configuration.Sources.Add(new MutableSource(provider));
        using var registry = new OidcClientRegistry(configuration, NullLogger<OidcClientRegistry>.Instance);
        provider.Replace(Entry("app", badRedirect));
        Assert.Contains(Redirect, (IReadOnlySet<string>)registry.Find("dingtalk", "app")!.RedirectUris);
        provider.Replace(Entry("new-app", Redirect));
        Assert.Null(registry.Find("dingtalk", "app"));
        Assert.NotNull(registry.Find("dingtalk", "new-app"));
    }

    [Fact]
    public void DuplicateRegistrationsAndScalarUpdates_AreRejectedAsAWhole()
    {
        var provider = new MutableConfiguration();
        provider.Replace(Entry("app", Redirect));
        using var configuration = new ConfigurationManager();
        configuration.Sources.Add(new MutableSource(provider));
        using var registry = new OidcClientRegistry(configuration, NullLogger<OidcClientRegistry>.Instance);
        var duplicate = Entry("app", Redirect);
        foreach (var entry in Entry("app", "https://other.example/callback"))
            duplicate.Add(entry.Key.Replace("Clients:0:", "Clients:1:"), entry.Value);
        provider.Replace(duplicate);
        Assert.Single(registry.Find("dingtalk", "app")!.RedirectUris);
        provider.Replace(new() { ["Clients"] = "typo" });
        Assert.NotNull(registry.Find("dingtalk", "app"));
    }

    [Fact]
    public void InvalidInitialClientConfiguration_FailsStartup()
    {
        using var configuration = new ConfigurationManager();
        configuration.AddInMemoryCollection(Entry("app", "https://client.example/callback#fragment"));
        Assert.Throws<OptionsValidationException>(() => new OidcClientRegistry(configuration, NullLogger<OidcClientRegistry>.Instance));
    }

    [Fact]
    public async Task BaseUrlAndSigningKey_CanBothComeFromJson()
    {
        using var factory = new FileFactory();
        using var client = factory.CreateClient();
        using var metadata = JsonDocument.Parse(await client.GetStringAsync("/dingtalk/.well-known/openid-configuration"));
        Assert.Equal("https://auth.example/bridge/dingtalk", metadata.RootElement.GetProperty("issuer").GetString());
        await AssertSigningKey(client, "reload test seed");
    }

    [Fact]
    public async Task EnvironmentProvider_OverridesJsonWithoutChangingConfigurationPrecedence()
    {
        // Use a unique provider prefix to avoid changing other parallel test hosts' environment.
        var prefix = "OIDCBRIDGE_TEST_" + Guid.NewGuid().ToString("N") + "_";
        var baseUrlVariable = prefix + "BaseUrl";
        var signingKeyVariable = prefix + "SigningKey";
        Environment.SetEnvironmentVariable(baseUrlVariable, "https://environment.example/subroute");
        Environment.SetEnvironmentVariable(signingKeyVariable, "environment signing seed");
        try
        {
            using var factory = new FileFactory(environmentPrefix: prefix);
            using var client = factory.CreateClient();
            var configuration = factory.Services.GetRequiredService<IConfiguration>();
            Assert.Equal("https://environment.example/subroute", configuration["BaseUrl"]);
            Assert.Equal("environment signing seed", configuration["SigningKey"]);
            using var metadata = JsonDocument.Parse(await client.GetStringAsync("/dingtalk/.well-known/openid-configuration"));
            Assert.Equal("https://environment.example/subroute/dingtalk", metadata.RootElement.GetProperty("issuer").GetString());
            await AssertSigningKey(client, "environment signing seed");
        }
        finally
        {
            Environment.SetEnvironmentVariable(baseUrlVariable, null);
            Environment.SetEnvironmentVariable(signingKeyVariable, null);
        }
    }

    private static async Task AssertSigningKey(HttpClient client, string expectedSeed)
    {
        using var expected = SigningKeyDerivation.Derive(expectedSeed);
        using var jwks = JsonDocument.Parse(await client.GetStringAsync("/dingtalk/jwks"));
        Assert.Equal(WebEncoders.Base64UrlEncode(expected.ExportParameters(false).Modulus!),
            jwks.RootElement.GetProperty("keys")[0].GetProperty("n").GetString());
    }

    [Fact]
    public async Task RealFileWatcher_AddsRemovesAndRecoversFromInvalidJsonWithoutRestart()
    {
        using var factory = new FileFactory();
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = false });
        var registry = factory.Services.GetRequiredService<OidcClientRegistry>();
        Assert.IsType<ReloadSafeJsonConfigurationProvider>(((IConfigurationRoot)factory.Services.GetRequiredService<IConfiguration>())
            .Providers.OfType<JsonConfigurationProvider>().Single());
        var jwks = await client.GetStringAsync("/dingtalk/jwks");
        var metadata = await client.GetStringAsync("/dingtalk/.well-known/openid-configuration");
        using var before = await Authorize(client, "new-app");
        Assert.Equal(HttpStatusCode.BadRequest, before.StatusCode);

        factory.Write("new-app", newBaseUrl: "https://changed.example", newSigningKey: "changed seed");
        await Until(() => registry.Find("dingtalk", "new-app") is not null);
        using var added = await Authorize(client, "new-app");
        Assert.Equal(HttpStatusCode.Redirect, added.StatusCode);
        Assert.Equal(jwks, await client.GetStringAsync("/dingtalk/jwks"));
        Assert.Equal(metadata, await client.GetStringAsync("/dingtalk/.well-known/openid-configuration"));

        factory.WriteRaw("{ invalid json");
        await Until(() => factory.Warnings.Messages.Any(message => message.Contains("malformed JSON")));
        using var malformed = await Authorize(client, "new-app");
        Assert.Equal(HttpStatusCode.Redirect, malformed.StatusCode);

        // Removing a previously malformed file must not leave a stale error flag pinning clients forever.
        factory.DeleteConfig();
        await Until(() => registry.Find("dingtalk", "new-app") is null);
        factory.Write("new-app");
        await Until(() => registry.Find("dingtalk", "new-app") is not null);

        factory.Write("new-app", "https://client.example/callback#invalid");
        await Until(() => factory.Warnings.Messages.Any(message => message.Contains("invalid Clients update")));
        using var invalid = await Authorize(client, "new-app");
        Assert.Equal(HttpStatusCode.Redirect, invalid.StatusCode);

        factory.Write(null);
        await Until(() => registry.Find("dingtalk", "new-app") is null);
        using var removed = await Authorize(client, "new-app");
        Assert.Equal(HttpStatusCode.BadRequest, removed.StatusCode);
        factory.Write("recovered-app");
        await Until(() => registry.Find("dingtalk", "recovered-app") is not null);
        using var recovered = await Authorize(client, "recovered-app");
        Assert.Equal(HttpStatusCode.Redirect, recovered.StatusCode);
    }

    [Fact]
    public async Task RemovingClientOrRedirect_BlocksExistingCallbackAndCodeAndRemovingClientBlocksUserinfo()
    {
        using var factory = new FileFactory();
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = false });
        var registry = factory.Services.GetRequiredService<OidcClientRegistry>();
        var pending = await Start(client);
        var code = await Callback(client, await Start(client));
        var accessCode = await Callback(client, await Start(client));
        using var tokens = await Token(client, accessCode);
        tokens.EnsureSuccessStatusCode();
        using var tokenBody = JsonDocument.Parse(await tokens.Content.ReadAsStringAsync());
        var accessToken = tokenBody.RootElement.GetProperty("access_token").GetString()!;

        factory.Write("app", "https://other.example/callback");
        await Until(() => registry.Find("dingtalk", "app")!.RedirectUris.Contains("https://other.example/callback"));
        using var callback = await CallbackRequest(client, pending);
        Assert.Equal(HttpStatusCode.BadRequest, callback.StatusCode);
        using var removedRedirect = await Token(client, code);
        Assert.Equal(HttpStatusCode.BadRequest, removedRedirect.StatusCode);
        Assert.Equal(1, factory.Upstream.TokenCalls);

        factory.Write(null);
        await Until(() => registry.Find("dingtalk", "app") is null);
        using var deletedClient = await Token(client, code);
        Assert.Equal(HttpStatusCode.BadRequest, deletedClient.StatusCode);
        using var info = new HttpRequestMessage(HttpMethod.Get, "/dingtalk/userinfo");
        info.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var deletedUserinfo = await client.SendAsync(info);
        Assert.Equal(HttpStatusCode.Unauthorized, deletedUserinfo.StatusCode);
    }

    [Fact]
    public void MalformedInitialJson_FailsInsteadOfSilentlyStartingEmpty()
    {
        using var factory = new FileFactory();
        factory.WriteRaw("{ invalid initial JSON");
        Assert.Throws<InvalidDataException>(() => factory.CreateClient());
    }

    private static Dictionary<string, string?> Entry(string id, string redirect, string scope = "") => new()
    {
        ["Clients:0:Provider"] = "dingtalk", ["Clients:0:ClientId"] = id,
        ["Clients:0:RedirectUris:0"] = redirect, ["Clients:0:UpstreamScope"] = scope
    };

    private static Task<HttpResponseMessage> Authorize(HttpClient client, string id = "app") => client.GetAsync(
        QueryHelpers.AddQueryString("/dingtalk/authorize", new Dictionary<string, string?>
        { ["response_type"] = "code", ["client_id"] = id, ["redirect_uri"] = Redirect, ["scope"] = "openid" }));

    private sealed record Pending(string State, string Cookie);
    private static async Task<Pending> Start(HttpClient client)
    {
        using var response = await Authorize(client);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return new(QueryHelpers.ParseQuery(response.Headers.Location!.Query)["state"].ToString(),
            response.Headers.GetValues("Set-Cookie").Single().Split(';')[0]);
    }
    private static async Task<string> Callback(HttpClient client, Pending pending)
    {
        using var response = await CallbackRequest(client, pending);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return QueryHelpers.ParseQuery(response.Headers.Location!.Query)["code"].ToString();
    }
    private static async Task<HttpResponseMessage> CallbackRequest(HttpClient client, Pending pending)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, QueryHelpers.AddQueryString("/dingtalk/callback",
            new Dictionary<string, string?> { ["state"] = pending.State, ["code"] = Guid.NewGuid().ToString("N") }));
        request.Headers.Add("Cookie", pending.Cookie);
        return await client.SendAsync(request);
    }
    private static Task<HttpResponseMessage> Token(HttpClient client, string code) => client.PostAsync("/dingtalk/token",
        new FormUrlEncodedContent(new Dictionary<string, string>
        { ["grant_type"] = "authorization_code", ["client_id"] = "app", ["client_secret"] = "secret", ["redirect_uri"] = Redirect, ["code"] = code }));

    private static async Task Until(Func<bool> predicate)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (!predicate() && DateTime.UtcNow < deadline) await Task.Delay(50);
        Assert.True(predicate(), "Configuration did not reload within 10 seconds.");
    }

    private sealed class FileFactory : WebApplicationFactory<Program>
    {
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "oidc-clients-" + Guid.NewGuid().ToString("N"));
        private readonly PhysicalFileProvider _files;
        private readonly string? _environmentPrefix;
        public readonly WarningLogger Warnings = new();
        public readonly StubProvider Upstream = new();
        public FileFactory(string? environmentPrefix = null)
        {
            _environmentPrefix = environmentPrefix;
            Directory.CreateDirectory(_directory);
            _files = new PhysicalFileProvider(_directory);
            Write("app");
        }
        public void Write(string? clientId, string redirect = Redirect, string newBaseUrl = "https://auth.example/bridge", string newSigningKey = "reload test seed") =>
            WriteRaw(JsonSerializer.Serialize(new
            {
                BaseUrl = newBaseUrl, SigningKey = newSigningKey,
                Clients = clientId is null ? Array.Empty<object>() :
                    [new { Provider = "dingtalk", ClientId = clientId, RedirectUris = new[] { redirect } }]
            }));
        public void WriteRaw(string contents)
        {
            var temporary = Path.Combine(_directory, "new.json");
            File.WriteAllText(temporary, contents);
            File.Move(temporary, Path.Combine(_directory, "clients.json"), overwrite: true);
        }
        public void DeleteConfig() => File.Delete(Path.Combine(_directory, "clients.json"));
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureAppConfiguration(configuration =>
            {
                configuration.Sources.Clear();
                configuration.Add(new JsonConfigurationSource
                { FileProvider = _files, Path = "clients.json", Optional = false, ReloadOnChange = true, ReloadDelay = 50 });
                if (_environmentPrefix is not null) configuration.AddEnvironmentVariables(_environmentPrefix);
            });
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IOAuthProvider>();
                services.AddSingleton<IOAuthProvider>(Upstream);
                services.AddSingleton<ILogger<OidcClientRegistry>>(Warnings);
            });
        }
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (!disposing) return;
            _files.Dispose();
            var fullPath = Path.GetFullPath(_directory);
            var expectedPrefix = Path.GetFullPath(Path.GetTempPath()) + "oidc-clients-";
            if (!fullPath.StartsWith(expectedPrefix, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Unsafe temporary directory cleanup.");
            if (Directory.Exists(fullPath)) Directory.Delete(fullPath, recursive: true);
        }
    }

    private sealed class WarningLogger : ILogger<OidcClientRegistry>
    {
        public readonly ConcurrentQueue<string> Messages = new();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error, Func<TState, Exception?, string> formatter)
        { if (level >= LogLevel.Warning) Messages.Enqueue(formatter(state, error)); }
    }
    private sealed class StubProvider : IOAuthProvider
    {
        public int TokenCalls;
        public string Name => "dingtalk";
        public IReadOnlyList<string> Scopes => ["openid"];
        public IReadOnlyList<string> Claims => ["sub"];
        public string Documentation => "https://example.com/docs";
        public string BuildAuthorizationUrl(AuthorizationRequest request) => QueryHelpers.AddQueryString("https://platform.example/authorize",
            new Dictionary<string, string?> { ["state"] = request.State });
        public Task<ProviderToken> ExchangeAuthorizationCodeAsync(TokenRequest request, CancellationToken ct)
        { Interlocked.Increment(ref TokenCalls); return Task.FromResult(new ProviderToken("upstream", 3600)); }
        public Task<object> GetUserInfoAsync(string token, CancellationToken ct) => Task.FromResult<object>(new { sub = "user-1" });
    }
    private sealed class MutableSource(MutableConfiguration provider) : IConfigurationSource
    { public IConfigurationProvider Build(IConfigurationBuilder builder) => provider; }
    private sealed class MutableConfiguration : ConfigurationProvider
    { public void Replace(Dictionary<string, string?> entries) { Data = entries; OnReload(); } }
}
