using System.Net.Http.Headers;
using System.Text.Json;

namespace OAuth2Bridge.Providers;

internal static class ProviderHttp
{
    public static HttpRequestMessage Request(HttpMethod method, string url, string? bearer = null)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("oauth2-bridge");
        if (bearer is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return request;
    }

    public static async Task<JsonDocument> ReadAsync(HttpResponseMessage response, string defaultError, CancellationToken cancellationToken)
    {
        if ((int)response.StatusCode >= 500 || (int)response.StatusCode == 429)
            throw new HttpRequestException("The upstream provider is unavailable.");
        var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            document.Dispose();
            throw new JsonException("Expected an upstream JSON object.");
        }
        if (!response.IsSuccessStatusCode || root.TryGetProperty("error", out _) ||
            NonZero(root, "ret") || NonZero(root, "error_code"))
        {
            var upstreamError = Text(root, "error");
            var status = (int)response.StatusCode;
            document.Dispose();
            if (upstreamError is "server_error" or "temporarily_unavailable")
                throw new HttpRequestException("The upstream provider is unavailable.");
            var error = defaultError == "invalid_token" ? defaultError : upstreamError switch
            {
                "invalid_client" or "incorrect_client_credentials" => "invalid_client",
                "invalid_grant" or "bad_verification_code" or "redirect_uri_mismatch" => "invalid_grant",
                "invalid_scope" => "invalid_scope",
                "invalid_request" => "invalid_request",
                _ => status == 401 ? "invalid_client" : defaultError
            };
            throw new OAuthProviderException(error, "The upstream provider rejected the request.");
        }
        return document;
    }

    public static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    public static string Id(JsonElement element, string name)
    {
        if (element.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.String or JsonValueKind.Number &&
            !string.IsNullOrWhiteSpace(value.ToString())) return value.ToString();
        throw new JsonException($"Missing upstream {name}.");
    }

    public static long? Lifetime(JsonElement element)
    {
        if (!element.TryGetProperty("expires_in", out var value)) return null;
        if (long.TryParse(value.ToString(), out var seconds) && seconds > 0) return seconds;
        throw new JsonException("Invalid upstream token lifetime.");
    }

    public static ProviderToken Token(JsonElement root, bool commaSeparatedScope = false)
    {
        var scope = Text(root, "scope");
        if (commaSeparatedScope && scope is not null) scope = scope.Replace(',', ' ');
        return new ProviderToken(Id(root, "access_token"), Lifetime(root), Text(root, "refresh_token"), scope);
    }

    public static void RequireRedirectUri(TokenRequest request)
    {
        if (!Uri.TryCreate(request.RedirectUri, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.Fragment))
            throw new OAuthProviderException("invalid_request", "redirect_uri is required and must match the authorization request.");
    }

    private static bool NonZero(JsonElement root, string name) => root.TryGetProperty(name, out var value) && value.ToString() != "0";
}
