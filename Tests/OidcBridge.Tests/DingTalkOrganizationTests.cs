using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using OidcBridge.Providers;
using static OidcBridge.Tests.ProviderFixture;

namespace OidcBridge.Tests;

public sealed class DingTalkOrganizationTests
{
    [Theory]
    [InlineData("other-org")]
    [InlineData(null)]
    public async Task AuthorizationRequiresTheConfiguredOrganization(string? corpId)
    {
        using var fixture = new ProviderFixture("dingtalk", _ => Task.FromResult(Json(JsonSerializer.Serialize(
            new { accessToken = "user-token", expireIn = 3600, corpId }))), Organization());
        var authorization = new Uri(fixture.Provider.BuildAuthorizationUrl(Authorization()));
        Assert.Equal("openid corpid", QueryHelpers.ParseQuery(authorization.Query)["scope"]);
        var failure = await Assert.ThrowsAsync<OAuthProviderException>(() => fixture.Provider.ExchangeAuthorizationCodeAsync(Token(), default));
        Assert.Equal("invalid_grant", failure.Error);
    }

    [Theory]
    [InlineData("member@enterprise.example", "member-subject", true, true)]
    [InlineData("member@elsewhere.example", "member-subject", true, false)]
    [InlineData("member@enterprise.example", "other-subject", true, false)]
    [InlineData("member@enterprise.example", "member-subject", false, false)]
    [InlineData(null, "member-subject", true, false)]
    public async Task OnlyTheCurrentDirectoryMembersOrganizationMailboxIsVerified(string? mailbox, string unionId, bool active, bool allowed)
    {
        using var fixture = new ProviderFixture("dingtalk", request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            var response = path switch
            {
                "/v1.0/oauth2/userAccessToken" => """{"accessToken":"user-token","expireIn":3600,"corpId":"test-org"}""",
                "/v1.0/contact/users/me" => """{"unionId":"member-subject","email":"personal@example.net"}""",
                "/v1.0/oauth2/accessToken" => """{"accessToken":"app-token"}""",
                "/topapi/user/getbyunionid" => """{"errcode":0,"result":{"userid":"member-id"}}""",
                "/topapi/v2/user/get" => JsonSerializer.Serialize(new
                    { errcode = 0, result = new { userid = "member-id", unionid = unionId, active, org_email = mailbox, email = "personal@example.net" } }),
                _ => throw new InvalidOperationException("Unexpected provider request.")
            };
            return Task.FromResult(Json(response));
        }, Organization());

        var token = await fixture.Provider.ExchangeAuthorizationCodeAsync(Token(), default);
        if (!allowed)
        {
            await Assert.ThrowsAsync<OAuthProviderException>(() => fixture.Provider.GetAuthorizationProfileAsync(token, Token(), default));
            return;
        }

        var profile = JsonSerializer.SerializeToElement(await fixture.Provider.GetAuthorizationProfileAsync(token, Token(), default));
        Assert.Equal(mailbox, profile.GetProperty("email").GetString());
        Assert.True(profile.GetProperty("email_verified").GetBoolean());
        var userInfo = JsonSerializer.SerializeToElement(await fixture.Provider.GetUserInfoAsync(token.AccessToken, default));
        Assert.Equal(JsonValueKind.Null, userInfo.GetProperty("email").ValueKind);
    }

    private static IConfiguration Organization() => new ConfigurationBuilder().AddInMemoryCollection(
        new Dictionary<string, string?>
        {
            ["DingTalkOrganization:CorpId"] = "test-org",
            ["DingTalkOrganization:EmailDomain"] = "enterprise.example"
        }).Build();
}
