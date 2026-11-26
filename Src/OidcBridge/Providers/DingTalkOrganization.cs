using System.Net.Mail;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace OidcBridge.Providers;

internal sealed class DingTalkOrganization(HttpClient client, string corpId, string emailDomain)
{
    public string CorpId { get; } = corpId;

    internal static DingTalkOrganization? FromConfiguration(HttpClient client, IConfiguration? configuration)
    {
        var expectedCorpId = configuration?["DingTalkOrganization:CorpId"];
        var trustedDomain = configuration?["DingTalkOrganization:EmailDomain"];
        if (expectedCorpId is null && trustedDomain is null)
        {
            return null;
        }
        if (string.IsNullOrWhiteSpace(expectedCorpId) || string.IsNullOrWhiteSpace(trustedDomain) ||
            Uri.CheckHostName(trustedDomain) != UriHostNameType.Dns || !trustedDomain.Contains('.'))
        {
            throw new InvalidOperationException("DingTalk organization mode requires a corporation ID and an enterprise email domain.");
        }
        return new DingTalkOrganization(client, expectedCorpId, trustedDomain);
    }

    internal async Task<string> ReadVerifiedEmailAsync(TokenRequest exchange, string unionId, CancellationToken cancellationToken)
    {
        var application = await PostAsync("https://api.dingtalk.com/v1.0/oauth2/accessToken",
            new { appKey = exchange.ClientId, appSecret = exchange.ClientSecret }, cancellationToken);
        var accessToken = ReadString(application, "accessToken");
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            throw Reject("DingTalk did not issue an organization access token.");
        }

        var mapping = await PostAsync(DirectoryEndpoint("user/getbyunionid", accessToken), new { unionid = unionId }, cancellationToken);
        var userId = ReadString(Result(mapping, "member lookup"), "userid");
        if (string.IsNullOrWhiteSpace(userId))
        {
            throw Reject("DingTalk could not match the authorized account to an organization member.");
        }

        var response = await PostAsync(DirectoryEndpoint("v2/user/get", accessToken), new { userid = userId }, cancellationToken);
        var member = Result(response, "member details");
        var mailbox = ReadString(member, "org_email");
        if (ReadString(member, "userid") != userId || ReadString(member, "unionid") != unionId ||
            !member.TryGetProperty("active", out var active) || active.ValueKind != JsonValueKind.True)
        {
            throw Reject("DingTalk did not confirm an active member with the authorized identity.");
        }
        if (string.IsNullOrWhiteSpace(mailbox))
        {
            throw Reject("DingTalk directory did not return an enterprise mailbox for this member.");
        }
        if (!MailAddress.TryCreate(mailbox, out var email) || email.Address != mailbox ||
            !StringComparer.OrdinalIgnoreCase.Equals(email.Host, emailDomain))
        {
            throw Reject("DingTalk enterprise mailbox does not match the configured email domain.");
        }

        return email.Address;
    }

    private async Task<JsonElement> PostAsync(string url, object payload, CancellationToken cancellationToken)
    {
        using var response = await client.PostAsJsonAsync(url, payload, cancellationToken);
        if ((int)response.StatusCode >= 500 || (int)response.StatusCode == 429)
        {
            throw new HttpRequestException("DingTalk organization directory is unavailable.");
        }
        if (!response.IsSuccessStatusCode)
        {
            throw Reject($"DingTalk organization request returned HTTP {(int)response.StatusCode}.");
        }
        using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw Reject("DingTalk organization returned an invalid response.");
        }
        return document.RootElement.Clone();
    }

    private static JsonElement Result(JsonElement response, string operation)
    {
        if (response.TryGetProperty("errcode", out var error) && error.ValueKind == JsonValueKind.Number && error.TryGetInt32(out var code))
        {
            if (code != 0)
            {
                throw Reject($"DingTalk organization {operation} returned error code {code}.");
            }
            if (response.TryGetProperty("result", out var result) && result.ValueKind == JsonValueKind.Object)
            {
                return result;
            }
        }
        throw Reject($"DingTalk organization {operation} returned an invalid response.");
    }

    private static string? ReadString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static string DirectoryEndpoint(string path, string accessToken) =>
        QueryHelpers.AddQueryString($"https://oapi.dingtalk.com/topapi/{path}", "access_token", accessToken);

    private static OAuthProviderException Reject(string message) => new("invalid_grant", message);
}
