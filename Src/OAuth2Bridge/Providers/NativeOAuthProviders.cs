namespace OAuth2Bridge.Providers;

// These providers already publish usable discovery documents. Clients should use
// their own OAuth/OIDC endpoints; the bridge does not proxy or reissue their tokens.
internal static class NativeOAuthProviders
{
    public static readonly NativeOAuthProvider[] All =
    [
        new("gitlab", "https://gitlab.com/.well-known/openid-configuration"),
        new("google", "https://accounts.google.com/.well-known/openid-configuration"),
        new("microsoft", "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"),
        new("slack", "https://slack.com/.well-known/openid-configuration"),
        new("linkedin", "https://www.linkedin.com/oauth/.well-known/openid-configuration"),
        new("discord", "https://discord.com/.well-known/openid-configuration"),
        new("apple", "https://appleid.apple.com/.well-known/openid-configuration")
    ];
}

internal sealed record NativeOAuthProvider(string Name, string Metadata);
