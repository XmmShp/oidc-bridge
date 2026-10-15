using OAuth2Bridge;
using OAuth2Bridge.Providers;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddOptions<OAuth2BridgeOptions>()
    .Bind(builder.Configuration)
    .Validate(options => Uri.TryCreate(options.BaseUrl, UriKind.Absolute, out var uri) &&
        uri.Scheme is "http" or "https" && !string.IsNullOrWhiteSpace(uri.Host) &&
        string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment),
        "BaseUrl is required and must be an absolute HTTP(S) URL without credentials, query, or fragment.")
    .ValidateOnStart();
AddProvider<FeishuOAuthProvider>();
AddProvider<DingTalkOAuthProvider>();
AddProvider<GitHubOAuthProvider>();
AddProvider<GiteeOAuthProvider>();
AddProvider<WeiboOAuthProvider>();
AddProvider<QqOAuthProvider>();
builder.Services.AddScoped<OAuthProviderRegistry>();
builder.Services.AddProblemDetails();

var app = builder.Build();
app.UseExceptionHandler();

app.MapGet("/", (OAuthProviderRegistry providers) => Results.Ok(new
{
    service = "oauth2-bridge",
    providers = providers.All.Select(provider => new
    {
        name = provider.Name,
        metadata = $"{OAuthRequestHelpers.ResolveBaseUrl(providers.Options)}/{provider.Name}/.well-known/oauth-authorization-server"
    }),
    direct_providers = NativeOAuthProviders.All
}));
app.MapOAuthEndpoints();
app.Run();

void AddProvider<TProvider>() where TProvider : class, IOAuthProvider
{
    // Some upstream APIs require credentials in their query string. Do not log those URLs
    // or follow redirects to a different upstream host.
    builder.Services.AddHttpClient<TProvider>().RemoveAllLoggers()
        .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false });
    builder.Services.AddTransient<IOAuthProvider>(services => services.GetRequiredService<TProvider>());
}

public partial class Program;
