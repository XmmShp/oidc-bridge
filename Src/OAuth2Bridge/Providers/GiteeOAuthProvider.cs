namespace OAuth2Bridge.Providers;

public sealed class GiteeOAuthProvider(HttpClient client) : FormOAuthProvider(client)
{
    public override string Name => "gitee";
    protected override string AuthorizeEndpoint => "https://gitee.com/oauth/authorize";
    protected override string TokenEndpoint => "https://gitee.com/oauth/token";
    protected override string DefaultScope => "user_info";
    public override IReadOnlyList<string> Scopes => ["user_info"];
    public override string Documentation => "https://gitee.com/api/v5/oauth_doc";

    public override async Task<object> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken)
    {
        var url = Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString("https://gitee.com/api/v5/user", "access_token", accessToken);
        using var request = ProviderHttp.Request(HttpMethod.Get, url);
        using var response = await Client.SendAsync(request, cancellationToken);
        using var document = await ProviderHttp.ReadAsync(response, "invalid_token", cancellationToken);
        var user = document.RootElement;
        return new
        {
            sub = ProviderHttp.Id(user, "id"),
            name = OAuthRequestHelpers.FirstNonEmpty(ProviderHttp.Text(user, "name"), ProviderHttp.Text(user, "login")),
            preferred_username = ProviderHttp.Text(user, "login"),
            picture = ProviderHttp.Text(user, "avatar_url"),
            email = ProviderHttp.Text(user, "email"),
            gitee = user.Clone()
        };
    }
}
