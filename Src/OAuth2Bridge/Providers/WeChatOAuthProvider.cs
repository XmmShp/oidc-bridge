using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace OAuth2Bridge.Providers;

public class WeChatOAuthProvider(HttpClient client, WeChatTokenCodec tokens, TimeProvider time) : IOAuthProvider
{
    public virtual string Name => "wechat";
    protected virtual string AuthorizeEndpoint => "https://open.weixin.qq.com/connect/qrconnect";
    protected virtual string DefaultScope => "snsapi_login";
    public virtual IReadOnlyList<string> Scopes => ["snsapi_login"];
    public IReadOnlyList<string> CodeChallengeMethods => [];
    public IReadOnlyList<string> Claims => ["sub", "name", "picture", "openid", "unionid"];
    public virtual string Documentation => "https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html";

    public string BuildAuthorizationUrl(AuthorizationRequest request)
    {
        if (!string.IsNullOrEmpty(request.CodeChallenge)) throw new OAuthProviderException("invalid_request", "WeChat does not support PKCE through this bridge.");
        var scope = string.IsNullOrWhiteSpace(request.Scope) ? DefaultScope : request.Scope;
        if (!Scopes.Contains(scope)) throw new OAuthProviderException("invalid_scope", "Unsupported scope for this WeChat application type.");
        return QueryHelpers.AddQueryString(AuthorizeEndpoint, new Dictionary<string, string?>
        {
            ["appid"] = request.ClientId, ["response_type"] = "code", ["redirect_uri"] = request.RedirectUri,
            ["scope"] = scope, ["state"] = request.State
        }) + "#wechat_redirect";
    }

    public async Task<ProviderToken> ExchangeAuthorizationCodeAsync(TokenRequest request, CancellationToken cancellationToken)
    {
        ProviderHttp.RequireRedirectUri(request);
        if (!string.IsNullOrEmpty(request.CodeVerifier)) throw new OAuthProviderException("invalid_request", "WeChat does not support PKCE through this bridge.");
        var url = QueryHelpers.AddQueryString("https://api.weixin.qq.com/sns/oauth2/access_token", new Dictionary<string, string?>
        {
            ["appid"] = request.ClientId, ["secret"] = request.ClientSecret, ["code"] = request.Code,
            ["grant_type"] = "authorization_code"
        });
        using var message = ProviderHttp.Request(HttpMethod.Get, url);
        using var response = await client.SendAsync(message, cancellationToken);
        using var document = await ProviderHttp.ReadAsync(response, "invalid_grant", cancellationToken);
        var data = document.RootElement;
        var token = ProviderHttp.Token(data, true);
        var seconds = token.ExpiresIn ?? throw new JsonException("Missing WeChat token lifetime.");
        var wrapped = tokens.Encode(Name, new WeChatToken(token.AccessToken, ProviderHttp.Id(data, "openid"), token.Scope,
            time.GetUtcNow().AddSeconds(seconds)));
        return token with { AccessToken = wrapped };
    }

    public async Task<object> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken)
    {
        var token = tokens.Decode(Name, accessToken);
        var parameters = new Dictionary<string, string?> { ["access_token"] = token.AccessToken, ["openid"] = token.OpenId };
        var basicScope = token.Scope?.Split(' ', ',').Contains("snsapi_base") == true;
        var endpoint = basicScope ? "https://api.weixin.qq.com/sns/auth" : "https://api.weixin.qq.com/sns/userinfo";
        if (!basicScope) parameters["lang"] = "zh_CN";
        using var request = ProviderHttp.Request(HttpMethod.Get, QueryHelpers.AddQueryString(endpoint, parameters));
        using var response = await client.SendAsync(request, cancellationToken);
        using var document = await ProviderHttp.ReadAsync(response, "invalid_token", cancellationToken);
        var user = document.RootElement;
        if (basicScope && (!user.TryGetProperty("errcode", out var resultCode) || resultCode.ToString() != "0"))
            throw new JsonException("Missing WeChat token validity result.");
        if (!basicScope && ProviderHttp.Id(user, "openid") != token.OpenId)
            throw new JsonException("WeChat returned a different user.");
        return new
        {
            sub = token.OpenId, name = ProviderHttp.Text(user, "nickname"), picture = ProviderHttp.Text(user, "headimgurl"),
            openid = token.OpenId, unionid = ProviderHttp.Text(user, "unionid"), wechat = user.Clone()
        };
    }
}

public sealed class WeChatOfficialAccountOAuthProvider(HttpClient client, WeChatTokenCodec tokens, TimeProvider time)
    : WeChatOAuthProvider(client, tokens, time)
{
    public override string Name => "wechat-mp";
    protected override string AuthorizeEndpoint => "https://open.weixin.qq.com/connect/oauth2/authorize";
    protected override string DefaultScope => "snsapi_userinfo";
    public override IReadOnlyList<string> Scopes => ["snsapi_base", "snsapi_userinfo"];
    public override string Documentation => "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html";
}
