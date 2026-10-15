using Microsoft.Extensions.Options;

namespace OidcBridge.Providers;

public sealed class OAuthProviderRegistry(IEnumerable<IOAuthProvider> providers, IOptions<OidcBridgeOptions> options)
{
    private readonly Dictionary<string, IOAuthProvider> _providers = providers.ToDictionary(p => p.Name, StringComparer.OrdinalIgnoreCase);
    public OidcBridgeOptions Options => options.Value;
    public IEnumerable<IOAuthProvider> All => _providers.Values;
    public IOAuthProvider? Find(string? name) => name is null ? null : _providers.GetValueOrDefault(name);
}
