using Microsoft.AspNetCore.WebUtilities;

namespace OAuth2Bridge.Providers;

public sealed class QqOAuthProvider(HttpClient client) : FormOAuthProvider(client)
{
    public override string Name => "qq";
    protected override string AuthorizeEndpoint => "https://graph.qq.com/oauth2.0/authorize";
    protected override string TokenEndpoint => "https://graph.qq.com/oauth2.0/token";
    protected override string DefaultScope => "get_user_info";
    protected override bool CommaSeparatedScope => true;
    public override IReadOnlyList<string> Scopes => ["get_user_info"];
    public override IReadOnlyList<string> Claims => ["sub", "name", "picture", "openid"];
    public override string Documentation => "https://wiki.connect.qq.com/使用authorization_code获取access_token";

    public override string BuildAuthorizationUrl(AuthorizationRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.State)) throw new OAuthProviderException("invalid_request", "QQ requires state.");
        return base.BuildAuthorizationUrl(request);
    }

    public override async Task<ProviderToken> ExchangeAuthorizationCodeAsync(TokenRequest request, CancellationToken cancellationToken)
    {
        ProviderHttp.RequireRedirectUri(request);
        if (!string.IsNullOrEmpty(request.CodeVerifier)) throw new OAuthProviderException("invalid_request", "QQ does not support PKCE through this bridge.");
        var url = QueryHelpers.AddQueryString(TokenEndpoint, new Dictionary<string, string?>
        {
            ["grant_type"] = "authorization_code", ["client_id"] = request.ClientId, ["client_secret"] = request.ClientSecret,
            ["code"] = request.Code, ["redirect_uri"] = request.RedirectUri, ["fmt"] = "json"
        });
        using var message = ProviderHttp.Request(HttpMethod.Get, url);
        using var response = await Client.SendAsync(message, cancellationToken);
        using var document = await ProviderHttp.ReadAsync(response, "invalid_grant", cancellationToken);
        return ProviderHttp.Token(document.RootElement, true);
    }

    public override async Task<object> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken)
    {
        var meUrl = QueryHelpers.AddQueryString("https://graph.qq.com/oauth2.0/me", new Dictionary<string, string?>
        { ["access_token"] = accessToken, ["fmt"] = "json" });
        using var meRequest = ProviderHttp.Request(HttpMethod.Get, meUrl);
        using var meResponse = await Client.SendAsync(meRequest, cancellationToken);
        using var me = await ProviderHttp.ReadAsync(meResponse, "invalid_token", cancellationToken);
        var subject = ProviderHttp.Id(me.RootElement, "openid");
        var appId = ProviderHttp.Id(me.RootElement, "client_id");
        var url = QueryHelpers.AddQueryString("https://graph.qq.com/user/get_user_info", new Dictionary<string, string?>
        { ["access_token"] = accessToken, ["oauth_consumer_key"] = appId, ["openid"] = subject });
        using var request = ProviderHttp.Request(HttpMethod.Get, url);
        using var response = await Client.SendAsync(request, cancellationToken);
        using var document = await ProviderHttp.ReadAsync(response, "invalid_token", cancellationToken);
        var user = document.RootElement;
        return new
        {
            sub = subject, name = ProviderHttp.Text(user, "nickname"),
            picture = OAuthRequestHelpers.FirstNonEmpty(ProviderHttp.Text(user, "figureurl_qq_2"), ProviderHttp.Text(user, "figureurl_qq_1")),
            openid = subject, qq = user.Clone()
        };
    }
}
