using System.Net;
using System.Text;
using OidcBridge.Providers;

namespace OidcBridge.Tests;

// Native adapters are tested independently from the bridge's OIDC protocol layer.
internal sealed class ProviderFixture : IDisposable
{
    private readonly HttpClient _client;
    public IOAuthProvider Provider { get; }

    public ProviderFixture(string provider, Func<HttpRequestMessage, Task<HttpResponseMessage>>? send = null)
    {
        _client = new HttpClient(new StubHandler(send ?? (_ => throw new InvalidOperationException("Unexpected upstream request."))));
        Provider = provider switch
        {
            "dingtalk" => new DingTalkOAuthProvider(_client), "feishu" => new FeishuOAuthProvider(_client),
            "github" => new GitHubOAuthProvider(_client), "gitee" => new GiteeOAuthProvider(_client),
            "qq" => new QqOAuthProvider(_client), "weibo" => new WeiboOAuthProvider(_client),
            _ => throw new ArgumentOutOfRangeException(nameof(provider))
        };
    }

    public static AuthorizationRequest Authorization(string scope = "", string challenge = "", string method = "", string prompt = "") =>
        new("app", "https://auth.example/provider/callback", "state", scope, challenge, method, prompt);
    public static TokenRequest Token(string verifier = "") => new("app", "secret", "native-code", "https://auth.example/provider/callback", verifier);
    public static HttpResponseMessage Json(string body, int status = 200) => new((HttpStatusCode)status)
    { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    public void Dispose() => _client.Dispose();

    private sealed class StubHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => send(request);
    }
}
