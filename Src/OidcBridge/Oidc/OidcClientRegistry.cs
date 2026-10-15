using System.Collections.Frozen;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace OidcBridge.Oidc;

// This is an immutable deployment-configuration snapshot, never login/session/token state.
public sealed class OidcClientRegistry : IDisposable
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<OidcClientRegistry> _logger;
    private readonly object _reloadLock = new();
    private readonly IDisposable _subscription;
    private FrozenDictionary<(string Provider, string ClientId), RegisteredOidcClient> _clients;

    public OidcClientRegistry(IConfiguration configuration, ILogger<OidcClientRegistry> logger)
    {
        _configuration = configuration;
        _logger = logger;
        _clients = ReadClients();
        _subscription = ChangeToken.OnChange(configuration.GetReloadToken, Reload);
    }

    public RegisteredOidcClient? Find(string provider, string clientId) =>
        Volatile.Read(ref _clients).GetValueOrDefault((provider.ToLowerInvariant(), clientId));

    private void Reload()
    {
        lock (_reloadLock)
        {
            try
            {
                if (_configuration is IConfigurationRoot root && root.Providers
                    .OfType<ReloadSafeJsonConfigurationProvider>().Any(provider => provider.HasReloadError))
                {
                    _logger.LogWarning("Ignoring malformed JSON configuration update; keeping the last valid Clients configuration.");
                    return;
                }
                var clients = ReadClients();
                Volatile.Write(ref _clients, clients);
                _logger.LogInformation("Clients configuration reloaded with {ClientCount} registrations.", clients.Count);
            }
            catch (OptionsValidationException)
            {
                _logger.LogWarning("Ignoring invalid Clients update; keeping the last valid configuration. Check provider/client IDs, duplicate registrations, and exact HTTPS redirect URIs (HTTP loopback is allowed).");
            }
        }
    }

    private FrozenDictionary<(string Provider, string ClientId), RegisteredOidcClient> ReadClients()
    {
        try
        {
            var section = _configuration.GetSection("Clients");
            // Reject scalar values rather than interpreting a typo as an intentional empty list.
            if (!string.IsNullOrEmpty(section.Value)) throw InvalidClients();
            var clients = section.Get<List<OidcClient>>() ?? [];
            var result = new Dictionary<(string Provider, string ClientId), RegisteredOidcClient>();
            foreach (var client in clients)
            {
                if (client is null || string.IsNullOrWhiteSpace(client.Provider) || string.IsNullOrWhiteSpace(client.ClientId) ||
                    client.RedirectUris is null || client.RedirectUris.Count == 0 ||
                    client.RedirectUris.Any(uri => !OidcService.ValidRedirectUri(uri))) throw InvalidClients();
                var registration = new RegisteredOidcClient(client.Provider, client.ClientId,
                    client.RedirectUris.ToFrozenSet(StringComparer.Ordinal), client.UpstreamScope ?? string.Empty);
                if (!result.TryAdd((client.Provider.ToLowerInvariant(), client.ClientId), registration)) throw InvalidClients();
            }
            return result.ToFrozenDictionary();
        }
        catch (Exception ex) when (ex is InvalidOperationException or FormatException)
        { throw InvalidClients(); }
    }

    private static OptionsValidationException InvalidClients() => new("Clients", typeof(OidcClient),
        ["Clients must contain unique provider/client_id pairs with explicit HTTPS redirect URIs (HTTP loopback is allowed)."]);

    public void Dispose() => _subscription.Dispose();
}

public sealed record RegisteredOidcClient(string Provider, string ClientId, FrozenSet<string> RedirectUris, string UpstreamScope);
