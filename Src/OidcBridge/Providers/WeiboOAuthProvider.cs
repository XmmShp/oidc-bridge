using Microsoft.AspNetCore.WebUtilities;

namespace OidcBridge.Providers;

public sealed class WeiboOAuthProvider(HttpClient client) : FormOAuthProvider(client)
{
    public override string Name => "weibo";
    protected override string AuthorizeEndpoint => "https://api.weibo.com/oauth2/authorize";
    protected override string TokenEndpoint => "https://api.weibo.com/oauth2/access_token";
    protected override bool CommaSeparatedScope => true;
    public override IReadOnlyList<string> Claims => ["sub", "name", "preferred_username", "picture"];
    public override string Documentation => "https://open.weibo.com/wiki/Oauth2/authorize";

    public override async Task<object> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken)
    {
        using var infoRequest = ProviderHttp.Request(HttpMethod.Post, "https://api.weibo.com/oauth2/get_token_info");
        infoRequest.Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["access_token"] = accessToken });
        using var infoResponse = await Client.SendAsync(infoRequest, cancellationToken);
        using var info = await ProviderHttp.ReadAsync(infoResponse, "invalid_token", cancellationToken);
        var subject = ProviderHttp.Id(info.RootElement, "uid");
        var url = QueryHelpers.AddQueryString("https://api.weibo.com/2/users/show.json", new Dictionary<string, string?>
        { ["access_token"] = accessToken, ["uid"] = subject });
        using var request = ProviderHttp.Request(HttpMethod.Get, url);
        using var response = await Client.SendAsync(request, cancellationToken);
        using var document = await ProviderHttp.ReadAsync(response, "invalid_token", cancellationToken);
        var user = document.RootElement;
        var returnedSubject = ProviderHttp.Text(user, "idstr") ?? ProviderHttp.Id(user, "id");
        if (returnedSubject != subject)
            throw new System.Text.Json.JsonException("Weibo returned a different user.");
        return new
        {
            sub = subject, name = ProviderHttp.Text(user, "screen_name"),
            preferred_username = ProviderHttp.Text(user, "screen_name"),
            picture = OAuthRequestHelpers.FirstNonEmpty(ProviderHttp.Text(user, "avatar_hd"), ProviderHttp.Text(user, "avatar_large"), ProviderHttp.Text(user, "profile_image_url")),
            weibo = user.Clone()
        };
    }
}
