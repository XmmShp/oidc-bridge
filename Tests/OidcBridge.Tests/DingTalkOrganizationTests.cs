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
    [InlineData("member@enterprise.example", "member-subject", true, false, true, true)]
    [InlineData("member@elsewhere.example", "member-subject", true, false, false, false)]
    [InlineData("member@enterprise.example", "other-subject", true, true, false, false)]
    [InlineData("member@enterprise.example", "member-subject", false, true, false, false)]
    [InlineData(null, "member-subject", true, false, false, false)]
    [InlineData(null, "member-subject", true, true, true, false)]
    [InlineData("member@elsewhere.example", "member-subject", true, true, true, false)]
    [InlineData("member@enterprise.example", "member-subject", true, true, true, true)]
    public async Task OnlyTheCurrentActiveMemberReceivesDirectoryClaims(
        string? mailbox, string unionId, bool active, bool includeDirectoryEmail, bool allowed, bool verified)
    {
        using var fixture = new ProviderFixture("dingtalk", request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            var response = path switch
            {
                "/v1.0/oauth2/userAccessToken" => """{"accessToken":"user-token","expireIn":3600,"corpId":"test-org"}""",
                "/v1.0/contact/users/me" => """{"unionId":"member-subject","email":"profile@example.net"}""",
                "/v1.0/oauth2/accessToken" => """{"accessToken":"app-token"}""",
                "/topapi/user/getbyunionid" => """{"errcode":0,"result":{"userid":"member-id"}}""",
                "/topapi/v2/user/get" => JsonSerializer.Serialize(new
                    { errcode = 0, result = new { userid = "member-id", unionid = unionId, active, org_email = mailbox, email = "personal@example.net" } }),
                _ => throw new InvalidOperationException("Unexpected provider request.")
            };
            return Task.FromResult(Json(response));
        }, Organization(includeDirectoryEmail));

        var token = await fixture.Provider.ExchangeAuthorizationCodeAsync(Token(), default);
        if (!allowed)
        {
            await Assert.ThrowsAsync<OAuthProviderException>(() => fixture.Provider.GetAuthorizationProfileAsync(token, Token(), default));
            return;
        }

        var profile = JsonSerializer.SerializeToElement(await fixture.Provider.GetAuthorizationProfileAsync(token, Token(), default));
        Assert.Equal(verified ? mailbox : null, profile.GetProperty("email").GetString());
        Assert.Equal(verified ? JsonValueKind.True : JsonValueKind.Null, profile.GetProperty("email_verified").ValueKind);
        Assert.Equal(verified ? null : "personal@example.net", profile.GetProperty("dingtalk_directory_email").GetString());
        var userInfo = JsonSerializer.SerializeToElement(await fixture.Provider.GetUserInfoAsync(token.AccessToken, default));
        Assert.Equal(JsonValueKind.Null, userInfo.GetProperty("email").ValueKind);
        Assert.Equal(JsonValueKind.Null, userInfo.GetProperty("dingtalk_directory_email").ValueKind);
    }

    private static IConfiguration Organization(bool includeDirectoryEmail = false) => new ConfigurationBuilder().AddInMemoryCollection(
        new Dictionary<string, string?>
        {
            ["DingTalkOrganization:CorpId"] = "test-org",
            ["DingTalkOrganization:EmailDomain"] = "enterprise.example",
            ["DingTalkOrganization:IncludeDirectoryEmail"] = includeDirectoryEmail.ToString()
        }).Build();
}
