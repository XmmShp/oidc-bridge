namespace OAuth2Bridge.Providers;

public sealed class GitHubOAuthProvider(HttpClient client) : FormOAuthProvider(client)
{
    public override string Name => "github";
    protected override string AuthorizeEndpoint => "https://github.com/login/oauth/authorize";
    protected override string TokenEndpoint => "https://github.com/login/oauth/access_token";
    protected override string DefaultScope => "read:user";
    protected override bool CommaSeparatedTokenScope => true;
    protected override bool SupportsPrompt => true;
    public override IReadOnlyList<string> CodeChallengeMethods => ["S256"];
    public override IReadOnlyList<string> Scopes => ["read:user", "user:email", "offline_access"];
    public override string Documentation => "https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps";

    public override async Task<object> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken)
    {
        using var document = await GetJsonAsync("https://api.github.com/user", accessToken, cancellationToken);
        var user = document.RootElement;
        return new
        {
            sub = ProviderHttp.Id(user, "id"),
            name = OAuthRequestHelpers.FirstNonEmpty(ProviderHttp.Text(user, "name"), ProviderHttp.Text(user, "login")),
            preferred_username = ProviderHttp.Text(user, "login"),
            picture = ProviderHttp.Text(user, "avatar_url"),
            email = ProviderHttp.Text(user, "email"),
            github = user.Clone()
        };
    }
}
