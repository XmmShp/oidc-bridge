using Microsoft.Extensions.Configuration.Json;

namespace OidcBridge;

internal static class ReloadSafeJsonConfiguration
{
    public static void KeepValidJsonOnReload(this ConfigurationManager configuration)
    {
        foreach (var original in configuration.Sources.OfType<JsonConfigurationSource>()
                     .Where(source => source is not ReloadSafeJsonConfigurationSource).ToArray())
        {
            // Replace each source in place so environment/command-line precedence stays unchanged.
            configuration.Sources[configuration.Sources.IndexOf(original)] = new ReloadSafeJsonConfigurationSource
            {
                Path = original.Path!, FileProvider = original.FileProvider, Optional = original.Optional,
                ReloadOnChange = original.ReloadOnChange, ReloadDelay = original.ReloadDelay,
                OnLoadException = original.OnLoadException
            };
        }
    }
}

internal sealed class ReloadSafeJsonConfigurationSource : JsonConfigurationSource
{
    public override IConfigurationProvider Build(IConfigurationBuilder builder)
    {
        EnsureDefaults(builder);
        return new ReloadSafeJsonConfigurationProvider(this);
    }
}

internal sealed class ReloadSafeJsonConfigurationProvider(JsonConfigurationSource source) : JsonConfigurationProvider(source)
{
    private bool _initialized;
    private bool _hasReloadError;
    public bool HasReloadError => _hasReloadError && Source.FileProvider?.GetFileInfo(Source.Path!).Exists == true;

    public override void Load()
    {
        base.Load();
        _initialized = true;
    }

    public override void Load(Stream stream)
    {
        try
        {
            // JsonConfigurationProvider assigns Data only after parsing the whole document.
            base.Load(stream);
            _hasReloadError = false;
        }
        catch (FormatException) when (_initialized)
        {
            // Do not let FileConfigurationProvider clear Data or throw on the watcher thread.
            // Initial malformed configuration still fails startup.
            _hasReloadError = true;
        }
    }
}
