using Microsoft.Extensions.Options;

namespace OAuth2Bridge.Providers;

public sealed class OAuthProviderRegistry(IEnumerable<IOAuthProvider> providers, IOptions<OAuth2BridgeOptions> options)
{
    private readonly Dictionary<string, IOAuthProvider> _providers = providers.ToDictionary(p => p.Name, StringComparer.OrdinalIgnoreCase);
    public OAuth2BridgeOptions Options => options.Value;
    public IEnumerable<IOAuthProvider> All => _providers.Values;
    public IOAuthProvider? Find(string? name) => name is null ? null : _providers.GetValueOrDefault(name);
}
