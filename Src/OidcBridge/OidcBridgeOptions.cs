namespace OidcBridge;

public sealed class OidcBridgeOptions
{
    public string BaseUrl { get; set; } = "http://localhost:5292";
    public string SigningKey { get; set; } = string.Empty;
}
