using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using OAuth2Bridge.Providers;
using static OAuth2Bridge.Tests.PublicProviderTests;

namespace OAuth2Bridge.Tests;

public sealed class WeChatProviderTests
{
    [Theory]
    [InlineData("wechat", "snsapi_login")]
    [InlineData("wechat-mp", "snsapi_userinfo")]
    [InlineData("wechat-mp", "snsapi_base")]
    public async Task TokenAndUserInfo_ProtectOpenIdAndSupportRepeatedUserInfo(string provider, string scope)
    {
        var calls = 0;
        using var factory = Factory(provider, (request, _) =>
        {
            calls++;
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal("api.weixin.qq.com", request.RequestUri!.Host);
            var query = QueryHelpers.ParseQuery(request.RequestUri.Query);
            if (calls == 1)
            {
                Assert.Equal("/sns/oauth2/access_token", request.RequestUri.AbsolutePath);
                Assert.Equal("app", query["appid"]);
                Assert.Equal("secret", query["secret"]);
                Assert.Equal("one-time-code", query["code"]);
                Assert.Equal("authorization_code", query["grant_type"]);
                return Task.FromResult(Json($$"""{"access_token":"upstream-secret-token","expires_in":7200,"refresh_token":"refresh","openid":"app-scoped-openid","scope":"{{scope}}"}"""));
            }
            Assert.Equal("upstream-secret-token", query["access_token"]);
            Assert.Equal("app-scoped-openid", query["openid"]);
            Assert.Null(request.Headers.Authorization);
            if (scope == "snsapi_base")
            {
                Assert.Equal("/sns/auth", request.RequestUri.AbsolutePath);
                return Task.FromResult(Json("{\"errcode\":0,\"errmsg\":\"ok\"}"));
            }
            Assert.Equal("/sns/userinfo", request.RequestUri.AbsolutePath);
            return Task.FromResult(Json("""{"openid":"app-scoped-openid","unionid":"union","nickname":"WeChat User","headimgurl":"https://example.com/avatar","country":"CN"}"""));
        });
        using var client = factory.CreateClient();
        using var tokenResponse = await client.PostAsync($"/{provider}/token", TokenForm());
        tokenResponse.EnsureSuccessStatusCode();
        using var token = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync());
        var bearer = token.RootElement.GetProperty("access_token").GetString()!;
        Assert.DoesNotContain("upstream-secret-token", bearer);
        Assert.DoesNotContain("app-scoped-openid", bearer);
        Assert.Equal("refresh", token.RootElement.GetProperty("refresh_token").GetString());
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        for (var index = 0; index < 2; index++)
        {
            using var userResponse = await client.GetAsync($"/{provider}/userinfo");
            userResponse.EnsureSuccessStatusCode();
            using var user = JsonDocument.Parse(await userResponse.Content.ReadAsStringAsync());
            Assert.Equal("app-scoped-openid", user.RootElement.GetProperty("sub").GetString());
            if (scope != "snsapi_base")
            {
                Assert.Equal("WeChat User", user.RootElement.GetProperty("name").GetString());
                Assert.Equal("CN", user.RootElement.GetProperty("wechat").GetProperty("country").GetString());
            }
            else Assert.Equal(JsonValueKind.Null, user.RootElement.GetProperty("name").ValueKind);
        }
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task ExpiredToken_IsRejectedBeforeUpstreamCall()
    {
        var time = new MutableTime();
        var calls = 0;
        using var factory = Factory("wechat", (_, _) =>
        {
            calls++;
            return Task.FromResult(Json("""{"access_token":"upstream","expires_in":60,"openid":"open","scope":"snsapi_login"}"""));
        }, time);
        using var client = factory.CreateClient();
        using var response = await client.PostAsync("/wechat/token", TokenForm());
        response.EnsureSuccessStatusCode();
        using var token = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        time.Advance(TimeSpan.FromSeconds(61));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.RootElement.GetProperty("access_token").GetString());
        using var user = await client.GetAsync("/wechat/userinfo");
        Assert.Equal(HttpStatusCode.Unauthorized, user.StatusCode);
        Assert.Contains("invalid_token", user.Headers.WwwAuthenticate.ToString());
        Assert.Equal(1, calls);
    }

    [Theory]
    [InlineData("upstream-token-without-openid")]
    [InlineData("not-a-protected-token!")]
    public async Task InvalidToken_IsRejectedBeforeUpstreamCall(string token)
    {
        using var factory = Factory("wechat", (_, _) => throw new InvalidOperationException("Should not call upstream."));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.GetAsync("/wechat/userinfo");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public void TokenProtection_RejectsDifferentProviderAndModifiedPayload()
    {
        var time = new MutableTime();
        var codec = new WeChatTokenCodec(new EphemeralDataProtectionProvider(), time);
        var token = codec.Encode("wechat", new WeChatToken("access", "open", "snsapi_login", time.GetUtcNow().AddMinutes(1)));
        Assert.Equal("open", codec.Decode("wechat", token).OpenId);
        Assert.Throws<OAuthProviderException>(() => codec.Decode("wechat-mp", token));
        var bytes = WebEncoders.Base64UrlDecode(token);
        bytes[bytes.Length / 2] ^= 1;
        Assert.Throws<OAuthProviderException>(() => codec.Decode("wechat", WebEncoders.Base64UrlEncode(bytes)));
    }

    [Theory]
    [InlineData("wechat", "snsapi_userinfo")]
    [InlineData("wechat-mp", "snsapi_login")]
    public async Task Authorization_RejectsScopesFromDifferentApplicationType(string provider, string scope)
    {
        using var factory = new OAuthBridgeFactory();
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        using var response = await client.GetAsync($"/{provider}/authorize?response_type=code&client_id=app&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&scope={scope}");
        Assert.Equal("invalid_scope", QueryHelpers.ParseQuery(response.Headers.Location!.Query)["error"]);
    }

    [Theory]
    [InlineData("{\"access_token\":\"access\",\"expires_in\":7200}")]
    [InlineData("{\"access_token\":\"access\",\"openid\":\"open\"}")]
    public async Task Token_RejectsIncompleteUpstreamResponses(string body)
    {
        using var factory = Factory("wechat", (_, _) => Task.FromResult(Json(body)));
        using var client = factory.CreateClient();
        using var response = await client.PostAsync("/wechat/token", TokenForm());
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
    }

    [Fact]
    public async Task UserInfo_RejectsUpstreamIdentityMismatch()
    {
        var calls = 0;
        using var factory = Factory("wechat", (_, _) => Task.FromResult(++calls == 1
            ? Json("""{"access_token":"access","openid":"expected","expires_in":7200,"scope":"snsapi_login"}""")
            : Json("""{"openid":"different","nickname":"Wrong User"}""")));
        using var client = factory.CreateClient();
        using var response = await client.PostAsync("/wechat/token", TokenForm());
        response.EnsureSuccessStatusCode();
        using var token = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.RootElement.GetProperty("access_token").GetString());
        using var user = await client.GetAsync("/wechat/userinfo");
        Assert.Equal(HttpStatusCode.BadGateway, user.StatusCode);
        Assert.DoesNotContain("Wrong User", await user.Content.ReadAsStringAsync());
    }

    private sealed class MutableTime : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 15, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }
}
