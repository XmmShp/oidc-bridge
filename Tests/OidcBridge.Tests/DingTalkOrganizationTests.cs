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
        using var fixture = DirectoryFixture(Organization(includeDirectoryEmail), mailbox, unionId, active);

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

    [Theory]
    [InlineData("client-id", "member-subject", "personal@example.net", true)]
    [InlineData("another-client", "member-subject", "personal@example.net", false)]
    [InlineData("client-id", "another-subject", "personal@example.net", false)]
    [InlineData("client-id", "member-subject", "changed@example.net", false)]
    public async Task VerifiedDirectoryAddressMustStillMatchTheClientSubjectAndAddress(
        string clientId, string subject, string email, bool verified)
    {
        var request = Token() with { ClientId = "client-id" };
        var configuration = Organization(includeDirectoryEmail: true, (clientId, subject, email));
        using var fixture = DirectoryFixture(configuration, null, "member-subject", true);
        var token = await fixture.Provider.ExchangeAuthorizationCodeAsync(request, default);
        var profile = JsonSerializer.SerializeToElement(await fixture.Provider.GetAuthorizationProfileAsync(token, request, default));
        Assert.Equal(verified ? "personal@example.net" : null, profile.GetProperty("email").GetString());
        Assert.Equal(verified ? JsonValueKind.True : JsonValueKind.Null, profile.GetProperty("email_verified").ValueKind);
        Assert.Equal(verified ? null : "personal@example.net", profile.GetProperty("dingtalk_directory_email").GetString());
        var userInfo = JsonSerializer.SerializeToElement(await fixture.Provider.GetUserInfoAsync(token.AccessToken, default));
        Assert.Equal(JsonValueKind.Null, userInfo.GetProperty("email").ValueKind);
        Assert.Equal(JsonValueKind.Null, userInfo.GetProperty("email_verified").ValueKind);
    }

    [Theory]
    [InlineData(false, "other-subject", "different@example.net")]
    [InlineData(true, "other-subject", "PERSONAL@example.net")]
    [InlineData(true, "member-subject", "different@example.net")]
    [InlineData(true, "other-subject", "Missing mailbox")]
    public void InvalidOrAmbiguousVerificationConfigurationFailsStartup(bool includeDirectoryEmail, string subject, string email)
    {
        var configuration = Organization(includeDirectoryEmail,
            ("client-id", "member-subject", "personal@example.net"), ("client-id", subject, email));
        using var client = new HttpClient();
        Assert.Throws<InvalidOperationException>(() => new DingTalkOAuthProvider(client, configuration));
    }

    private static ProviderFixture DirectoryFixture(IConfiguration configuration, string? mailbox, string unionId, bool active) =>
        new("dingtalk", request =>
        {
            var response = request.RequestUri!.AbsolutePath switch
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
        }, configuration);

    private static IConfiguration Organization(bool includeDirectoryEmail = false,
        params (string ClientId, string Subject, string Email)[] verifiedEmails)
    {
        var settings = new Dictionary<string, string?>
        {
            ["DingTalkOrganization:CorpId"] = "test-org",
            ["DingTalkOrganization:EmailDomain"] = "enterprise.example",
            ["DingTalkOrganization:IncludeDirectoryEmail"] = includeDirectoryEmail.ToString()
        };
        for (var i = 0; i < verifiedEmails.Length; i++)
        {
            var entry = verifiedEmails[i];
            var prefix = $"DingTalkOrganization:VerifiedDirectoryEmails:{i}";
            settings[$"{prefix}:ClientId"] = entry.ClientId;
            settings[$"{prefix}:Subject"] = entry.Subject;
            settings[$"{prefix}:Email"] = entry.Email;
        }
        return new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
    }
}
