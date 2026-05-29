sealed class OAuth2BridgeOptions
{
    public string PublicEndpointPrefix { get; set; } = string.Empty;

    public string AuthorizeEndpoint { get; set; } = "https://login.dingtalk.com/oauth2/auth";

    public string DingTalkScope { get; set; } = "openid";
}
