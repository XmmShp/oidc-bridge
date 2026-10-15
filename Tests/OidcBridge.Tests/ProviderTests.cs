using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using OidcBridge.Providers;
using static OidcBridge.Tests.ProviderFixture;

namespace OidcBridge.Tests;

public sealed class ProviderTests
{
    [Theory]
    [InlineData("dingtalk", "https://login.dingtalk.com/oauth2/auth", "openid")]
    [InlineData("feishu", "https://accounts.feishu.cn/open-apis/authen/v1/authorize", null)]
    [InlineData("github", "https://github.com/login/oauth/authorize", "read:user")]
    [InlineData("gitee", "https://gitee.com/oauth/authorize", "user_info")]
    [InlineData("qq", "https://graph.qq.com/oauth2.0/authorize", "get_user_info")]
    [InlineData("weibo", "https://api.weibo.com/oauth2/authorize", null)]
    public void Authorization_UsesNativeEndpointAndDefaultPermissions(string name, string endpoint, string? scope)
    {
        using var fixture = new ProviderFixture(name);
        var request = Authorization() with { State = "a+b&中文" };
        var uri = new Uri(fixture.Provider.BuildAuthorizationUrl(request));
        Assert.Equal(endpoint, uri.GetLeftPart(UriPartial.Path));
        var query = QueryHelpers.ParseQuery(uri.Query);
        Assert.Equal(request.ClientId, query["client_id"]);
        Assert.Equal(request.RedirectUri, query["redirect_uri"]);
        Assert.Equal(request.State, query["state"]);
        if (scope is null) Assert.False(query.ContainsKey("scope"));
        else Assert.Equal(scope, query["scope"]);
        if (name == "dingtalk") Assert.Equal("consent", query["prompt"]);
    }

    [Theory]
    [InlineData("dingtalk")]
    [InlineData("gitee")]
    [InlineData("qq")]
    [InlineData("weibo")]
    public void Authorization_RejectsUnsupportedNativePkce(string name)
    {
        using var fixture = new ProviderFixture(name);
        Assert.Equal("invalid_request", Assert.Throws<OAuthProviderException>(() =>
            fixture.Provider.BuildAuthorizationUrl(Authorization(challenge: "challenge", method: "S256"))).Error);
    }

    [Theory]
    [InlineData("github")]
    [InlineData("feishu")]
    public void Authorization_ForwardsNativePkceAndPrompt(string name)
    {
        using var fixture = new ProviderFixture(name);
        var uri = new Uri(fixture.Provider.BuildAuthorizationUrl(Authorization("first second", "challenge", "S256", "consent")));
        var query = QueryHelpers.ParseQuery(uri.Query);
        Assert.Equal("challenge", query["code_challenge"]);
        Assert.Equal("S256", query["code_challenge_method"]);
        Assert.Equal("first second", query["scope"]);
        Assert.Equal("consent", query["prompt"]);
    }

    [Theory]
    [InlineData("qq")]
    [InlineData("weibo")]
    public void Authorization_ConvertsNativeScopeSeparator(string name)
    {
        using var fixture = new ProviderFixture(name);
        var query = QueryHelpers.ParseQuery(new Uri(fixture.Provider.BuildAuthorizationUrl(Authorization("first second"))).Query);
        Assert.Equal("first,second", query["scope"]);
    }

    [Fact]
    public void Qq_RequiresState()
    {
        using var fixture = new ProviderFixture("qq");
        Assert.Throws<OAuthProviderException>(() => fixture.Provider.BuildAuthorizationUrl(Authorization() with { State = "" }));
    }

    [Theory]
    [InlineData("dingtalk", "https://api.dingtalk.com/v1.0/oauth2/userAccessToken")]
    [InlineData("feishu", "https://accounts.feishu.cn/oauth/v3/token")]
    [InlineData("github", "https://github.com/login/oauth/access_token")]
    [InlineData("gitee", "https://gitee.com/oauth/token")]
    [InlineData("qq", "https://graph.qq.com/oauth2.0/token")]
    [InlineData("weibo", "https://api.weibo.com/oauth2/access_token")]
    public async Task Token_TranslatesNativeCredentialsAndReturnsOriginalToken(string name, string endpoint)
    {
        var verifier = name is "github" or "feishu" ? "native-verifier" : "";
        var called = false;
        using var fixture = new ProviderFixture(name, async request =>
        {
            called = true;
            Assert.Equal(endpoint, request.RequestUri!.GetLeftPart(UriPartial.Path));
            Assert.Null(request.Headers.Authorization);
            var parameters = name == "qq" ? QueryHelpers.ParseQuery(request.RequestUri.Query)
                .ToDictionary(pair => pair.Key, pair => pair.Value.ToString()) :
                name is "feishu" or "dingtalk" ? JsonSerializer.Deserialize<Dictionary<string, string>>(await request.Content!.ReadAsStringAsync())! :
                QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync()).ToDictionary(pair => pair.Key, pair => pair.Value.ToString());
            Assert.Equal("app", parameters[name == "dingtalk" ? "clientId" : "client_id"]);
            Assert.Equal("secret", parameters[name == "dingtalk" ? "clientSecret" : "client_secret"]);
            Assert.Equal("native-code", parameters["code"]);
            if (name != "dingtalk") Assert.Equal("https://auth.example/provider/callback", parameters["redirect_uri"]);
            if (verifier.Length > 0) Assert.Equal(verifier, parameters["code_verifier"]);
            if (name == "qq") { Assert.Equal(HttpMethod.Get, request.Method); Assert.Equal("json", parameters["fmt"]); }
            else Assert.Equal(HttpMethod.Post, request.Method);
            return name == "dingtalk" ? Json("""{"accessToken":"native-access","expireIn":3600,"refreshToken":"native-refresh"}""") :
                Json("""{"access_token":"native-access","expires_in":3600,"refresh_token":"native-refresh","scope":"one,two"}""");
        });
        var token = await fixture.Provider.ExchangeAuthorizationCodeAsync(Token(verifier), default);
        Assert.True(called);
        Assert.Equal("native-access", token.AccessToken);
        Assert.Equal("native-refresh", token.RefreshToken);
        Assert.Equal(3600, token.ExpiresIn);
        Assert.Equal("Bearer", token.TokenType);
        if (name != "dingtalk") Assert.Equal(name is "github" or "weibo" or "qq" ? "one two" : "one,two", token.Scope);
    }

    [Fact]
    public async Task GitHub_DoesNotInventNativeTokenLifetime()
    {
        using var fixture = new ProviderFixture("github", _ => Task.FromResult(Json("""{"access_token":"access"}""")));
        Assert.Null((await fixture.Provider.ExchangeAuthorizationCodeAsync(Token(), default)).ExpiresIn);
    }

    [Theory]
    [InlineData("github", "{\"error\":\"incorrect_client_credentials\",\"error_description\":\"private-data\"}", "invalid_client")]
    [InlineData("github", "{\"error\":\"bad_verification_code\"}", "invalid_grant")]
    [InlineData("gitee", "{\"error\":\"invalid_grant\"}", "invalid_grant")]
    [InlineData("weibo", "{\"error_code\":21325,\"error\":\"private-data\"}", "invalid_grant")]
    [InlineData("qq", "{\"error\":100020,\"error_description\":\"private-data\"}", "invalid_grant")]
    [InlineData("feishu", "{\"code\":20002,\"error\":\"invalid_client\"}", "invalid_client")]
    [InlineData("dingtalk", "{\"code\":\"InvalidCode\",\"message\":\"private-data\"}", "invalid_grant")]
    public async Task Token_MapsNativeFailuresWithoutLeakingBodies(string name, string body, string expectedError)
    {
        using var fixture = new ProviderFixture(name, _ => Task.FromResult(Json(body)));
        var error = await Assert.ThrowsAsync<OAuthProviderException>(() => fixture.Provider.ExchangeAuthorizationCodeAsync(Token(), default));
        Assert.Equal(expectedError, error.Error);
        Assert.DoesNotContain("private-data", error.Message);
    }

    [Theory]
    [InlineData("{\"code\":20003,\"error_description\":\"private-data\"}", "Feishu rejected the token request (upstream code 20003).")]
    [InlineData("{\"code\":\"private-data\",\"error\":\"invalid_grant\"}", "Feishu rejected the token request.")]
    public async Task Feishu_OnlyExposesNumericFailureCodes(string body, string expectedMessage)
    {
        using var fixture = new ProviderFixture("feishu", _ => Task.FromResult(Json(body)));
        var error = await Assert.ThrowsAsync<OAuthProviderException>(() => fixture.Provider.ExchangeAuthorizationCodeAsync(Token(), default));
        Assert.Equal(expectedMessage, error.Message);
        Assert.DoesNotContain("private-data", error.Message);
    }

    [Theory]
    [InlineData("dingtalk")]
    [InlineData("feishu")]
    [InlineData("github")]
    [InlineData("gitee")]
    [InlineData("qq")]
    [InlineData("weibo")]
    public async Task Token_RejectsRateLimitsAndMalformedResponses(string name)
    {
        using (var unavailable = new ProviderFixture(name, _ => Task.FromResult(Json("private-data", 429))))
            await Assert.ThrowsAsync<HttpRequestException>(() => unavailable.Provider.ExchangeAuthorizationCodeAsync(Token(), default));
        foreach (var body in new[] { "not-json", "[]", "{}" })
        {
            using var malformed = new ProviderFixture(name, _ => Task.FromResult(Json(body)));
            await Assert.ThrowsAnyAsync<JsonException>(() => malformed.Provider.ExchangeAuthorizationCodeAsync(Token(), default));
        }
    }

    [Theory]
    [InlineData("dingtalk", "{\"unionId\":\"subject\",\"nick\":\"Test User\",\"mobile\":\"123\",\"loginEmail\":\"test@example.com\"}", "subject")]
    [InlineData("feishu", "{\"code\":0,\"data\":{\"open_id\":\"subject\",\"union_id\":\"different\",\"name\":\"Test User\",\"mobile\":\"123\"}}", "subject")]
    [InlineData("github", "{\"id\":9223372036854775807,\"login\":\"Test User\",\"name\":null}", "9223372036854775807")]
    [InlineData("gitee", "{\"id\":123,\"login\":\"login\",\"name\":\"Test User\"}", "123")]
    public async Task UserInfo_NormalizesStableSubjectsAndNativeAuthentication(string name, string body, string subject)
    {
        using var fixture = new ProviderFixture(name, request =>
        {
            if (name == "dingtalk") Assert.Equal("native-access", request.Headers.GetValues("x-acs-dingtalk-access-token").Single());
            else if (name == "gitee") Assert.Equal("native-access", QueryHelpers.ParseQuery(request.RequestUri!.Query)["access_token"]);
            else Assert.Equal("Bearer native-access", request.Headers.Authorization!.ToString());
            return Task.FromResult(Json(body));
        });
        var user = JsonSerializer.SerializeToElement(await fixture.Provider.GetUserInfoAsync("native-access", default));
        Assert.Equal(subject, user.GetProperty("sub").GetString());
        Assert.Equal("Test User", user.GetProperty("name").GetString());
        Assert.True(user.TryGetProperty(name, out _));
    }

    [Theory]
    [InlineData("dingtalk", "{\"nick\":\"missing-subject\"}")]
    [InlineData("feishu", "{\"code\":0,\"data\":{\"union_id\":\"wrong-subject-type\"}}")]
    [InlineData("github", "{\"login\":\"missing-id\"}")]
    [InlineData("gitee", "{\"login\":\"missing-id\"}")]
    public async Task UserInfo_RejectsProfilesWithoutStableSubjects(string name, string body)
    {
        using var fixture = new ProviderFixture(name, _ => Task.FromResult(Json(body)));
        await Assert.ThrowsAsync<JsonException>(() => fixture.Provider.GetUserInfoAsync("native-access", default));
    }

    [Theory]
    [InlineData("dingtalk")]
    [InlineData("feishu")]
    [InlineData("github")]
    [InlineData("gitee")]
    [InlineData("qq")]
    [InlineData("weibo")]
    public async Task UserInfo_MapsRejectedTokens(string name)
    {
        using var fixture = new ProviderFixture(name, _ => Task.FromResult(Json("{\"error\":\"invalid_token\"}", 401)));
        var error = await Assert.ThrowsAsync<OAuthProviderException>(() => fixture.Provider.GetUserInfoAsync("expired", default));
        Assert.Equal("invalid_token", error.Error);
    }

    [Fact]
    public async Task Qq_ResolvesOpenIdAndAppIdBeforeFetchingProfile()
    {
        var calls = 0;
        using var fixture = new ProviderFixture("qq", request =>
        {
            calls++;
            var query = QueryHelpers.ParseQuery(request.RequestUri!.Query);
            Assert.Equal("native-access", query["access_token"]);
            if (calls == 1)
            {
                Assert.Equal("/oauth2.0/me", request.RequestUri.AbsolutePath);
                Assert.Equal("json", query["fmt"]);
                return Task.FromResult(Json("""{"openid":"qq-open","client_id":"qq-app"}"""));
            }
            Assert.Equal("/user/get_user_info", request.RequestUri.AbsolutePath);
            Assert.Equal("qq-open", query["openid"]);
            Assert.Equal("qq-app", query["oauth_consumer_key"]);
            return Task.FromResult(Json("""{"ret":0,"nickname":"QQ User"}"""));
        });
        var user = JsonSerializer.SerializeToElement(await fixture.Provider.GetUserInfoAsync("native-access", default));
        Assert.Equal("qq-open", user.GetProperty("sub").GetString());
        Assert.Equal(2, calls);
    }

    [Theory]
    [InlineData("123", false)]
    [InlineData("456", true)]
    public async Task Weibo_UsesTokenOwnerAndRejectsSubjectMismatch(string returnedId, bool fails)
    {
        var calls = 0;
        using var fixture = new ProviderFixture("weibo", async request =>
        {
            calls++;
            if (calls == 1)
            {
                Assert.Equal("/oauth2/get_token_info", request.RequestUri!.AbsolutePath);
                Assert.Contains("access_token=native-access", await request.Content!.ReadAsStringAsync());
                return Json("""{"uid":123}""");
            }
            Assert.Equal("123", QueryHelpers.ParseQuery(request.RequestUri!.Query)["uid"]);
            return Json(JsonSerializer.Serialize(new { idstr = returnedId, screen_name = "Weibo User" }));
        });
        if (fails) await Assert.ThrowsAsync<JsonException>(() => fixture.Provider.GetUserInfoAsync("native-access", default));
        else
        {
            var user = JsonSerializer.SerializeToElement(await fixture.Provider.GetUserInfoAsync("native-access", default));
            Assert.Equal("123", user.GetProperty("sub").GetString());
        }
        Assert.Equal(2, calls);
    }
}
