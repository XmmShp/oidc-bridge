using System.Text.Json.Serialization;

namespace OidcBridge;

internal sealed record OAuthError(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("error_description")] string ErrorDescription);
