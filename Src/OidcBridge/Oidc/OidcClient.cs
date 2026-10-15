namespace OidcBridge.Oidc;

public sealed class OidcClient
{
    public string Provider { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public List<string> RedirectUris { get; set; } = [];
    // Native platform permissions, independent of the OIDC claims scopes.
    public string UpstreamScope { get; set; } = string.Empty;
}
