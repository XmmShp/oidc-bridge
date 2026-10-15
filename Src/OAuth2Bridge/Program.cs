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
builder.Services.AddHttpClient<FeishuOAuthProvider>();
builder.Services.AddTransient<IOAuthProvider>(services => services.GetRequiredService<FeishuOAuthProvider>());
builder.Services.AddHttpClient<DingTalkOAuthProvider>();
builder.Services.AddTransient<IOAuthProvider>(services => services.GetRequiredService<DingTalkOAuthProvider>());
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
    })
}));
app.MapOAuthEndpoints();
app.Run();

public partial class Program;
