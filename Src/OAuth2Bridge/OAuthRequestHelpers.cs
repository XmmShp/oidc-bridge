using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace OAuth2Bridge;

internal static class OAuthRequestHelpers
{
    public static IResult AuthorizationError(string redirectUri, string state, string error, string description)
    {
        if (Uri.TryCreate(redirectUri, UriKind.Absolute, out _))
        {
            var callbackUrl = QueryHelpers.AddQueryString(
                redirectUri,
                new Dictionary<string, string?>
                {
                    ["error"] = error,
                    ["error_description"] = description,
                    ["state"] = state
                });

            return Results.Redirect(callbackUrl);
        }

        return Results.BadRequest(new OAuthError(error, description));
    }

    public static async Task<Dictionary<string, string>> ReadRequestParametersAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        if (request.HasFormContentType)
        {
            var form = await request.ReadFormAsync(cancellationToken);
            return form.ToDictionary(pair => pair.Key, pair => pair.Value.ToString(), StringComparer.Ordinal);
        }

        if (request.ContentType?.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) == true)
        {
            var body = await JsonSerializer.DeserializeAsync<Dictionary<string, string>>(
                request.Body,
                JsonSerializerOptions.Web,
                cancellationToken);
            return body ?? [];
        }

        return request.Query.ToDictionary(pair => pair.Key, pair => pair.Value.ToString(), StringComparer.Ordinal);
    }

    public static string GetRequired(Dictionary<string, string> parameters, string key) =>
        parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : string.Empty;

    public static string GetOptional(Dictionary<string, string> parameters, string key) =>
        parameters.TryGetValue(key, out var value) ? value : string.Empty;

    public static string GetClientId(HttpRequest request, Dictionary<string, string> parameters)
    {
        var (username, _) = ReadBasicCredentials(request);
        return request.Headers.ContainsKey("Authorization") ? username : GetOptional(parameters, "client_id");
    }

    public static string GetClientSecret(HttpRequest request, Dictionary<string, string> parameters)
    {
        var (_, password) = ReadBasicCredentials(request);
        return request.Headers.ContainsKey("Authorization") ? password : GetOptional(parameters, "client_secret");
    }

    public static (string Username, string Password) ReadBasicCredentials(HttpRequest request)
    {
        var authorization = request.Headers.Authorization.ToString();
        if (!authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            return (string.Empty, string.Empty);
        }

        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(authorization["Basic ".Length..].Trim()));
            var separatorIndex = decoded.IndexOf(':', StringComparison.Ordinal);
            if (separatorIndex < 0)
            {
                return (decoded, string.Empty);
            }

            return (
                System.Net.WebUtility.UrlDecode(decoded[..separatorIndex]),
                System.Net.WebUtility.UrlDecode(decoded[(separatorIndex + 1)..]));
        }
        catch (FormatException)
        {
            return (string.Empty, string.Empty);
        }
    }

    public static string FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(static value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    public static string ResolveBaseUrl(OAuth2BridgeOptions options) => options.BaseUrl.Trim().TrimEnd('/');

}
