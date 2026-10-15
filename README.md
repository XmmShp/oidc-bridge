# oauth2-bridge

`oauth2-bridge` converts platform-specific OAuth capabilities into a consistent OAuth 2.0 authorization-code interface. It is an ASP.NET Core (`net10.0`) service for clients such as identity brokers and web applications.

The initial adapters support **DingTalk** and **Feishu**. Clients use the same authorization, token, discovery, and user information endpoints for either platform.

## Architecture

```text
OAuth client → shared OAuth endpoints → IOAuthProvider
                                       ├── DingTalkOAuthProvider → DingTalk HTTP OpenAPI
                                       └── FeishuOAuthProvider   → Feishu HTTP APIs
```

- `OAuthEndpoints` owns routing, common request validation, client authentication parsing, and OAuth responses.
- `OAuthProviderRegistry` resolves the adapter by the required provider name in the URL.
- Each `IOAuthProvider` implementation owns platform authorization parameters, token exchange, upstream errors, and user claim normalization.
- Both platform adapters call OpenAPI directly using typed `HttpClient` instances with request cancellation support.

To add a platform, implement `IOAuthProvider` and register it with dependency injection. Shared endpoints discover the registration without new platform-specific routes or conditionals.

## Endpoints

Replace `{provider}` with `dingtalk` or `feishu`:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/` | Service information and available providers |
| GET | `/{provider}/.well-known/oauth-authorization-server` | Provider metadata |
| GET | `/.well-known/oauth-authorization-server/{provider}` | RFC 8414 discovery for the provider issuer |
| GET | `/{provider}/authorize` | Redirect to the platform authorization page |
| POST | `/{provider}/token` | Exchange an authorization code |
| GET | `/{provider}/userinfo` | Fetch normalized user claims using a bearer token |

OAuth endpoints require an explicit provider. Unprefixed `/authorize`, `/token`, `/userinfo`, and discovery endpoints return HTTP 404, as do unknown providers.

This service implements OAuth 2.0 and does not expose OpenID Connect discovery endpoints, issue ID tokens, or expose JWKS. Use a generic OAuth client integration.

## Authorization flow

1. Redirect the browser to `/{provider}/authorize?response_type=code&client_id=...&redirect_uri=...&state=...`.
2. The bridge redirects to the platform. The original `redirect_uri` and `state` are preserved.
3. The platform redirects directly to the client callback with an authorization code. The client validates `state`.
4. POST `grant_type=authorization_code`, `code`, and the platform credentials to `/{provider}/token`. For Feishu, also send the identical `redirect_uri`. Use `application/x-www-form-urlencoded`; JSON is accepted for compatibility.
5. Call `/{provider}/userinfo` with `Authorization: Bearer <access_token>` on the same provider.

Use DingTalk AppKey/AppSecret or Feishu App ID/App Secret as `client_id`/`client_secret`. Token requests support `client_secret_basic` and `client_secret_post`. Credentials are passed to the selected platform; they are not stored in service configuration.

There is no bridge callback or independent client registration. Register the downstream client's callback URL in the platform console. Authorization-code validation, token lifetime, and application permissions are enforced by the platform. Tokens are upstream tokens, not tokens issued by this service. Only `authorization_code` is supported; refresh-token grants are not implemented.

### Platform differences

- **DingTalk:** calls `POST /v1.0/oauth2/userAccessToken` with camelCase JSON fields and `GET /v1.0/contact/users/me` with the `x-acs-dingtalk-access-token` header. Authorization redirects always include `prompt=consent`. The authorization request supplies `scope`, defaulting to `openid` when omitted. PKCE authorization requests are rejected because this adapter does not support PKCE.
- **Feishu:** uses the current v3 token endpoint, with JSON request translation. The authorization request supplies `scope` using Feishu permission names; when omitted, the parameter is left out. `code_challenge`, `code_challenge_method`, `code_verifier`, and `prompt` are forwarded. The platform validates PKCE and callback matching.

Both adapters return `sub`, `name`, `picture`, `email`, and `phone_number` when available. DingTalk preserves its existing extra fields and raw `dingtalk` object. Feishu returns `open_id`, `union_id`, `user_id`, and raw `feishu` data. Feishu `sub` consistently uses the application-scoped `open_id`. Optional profile fields depend on platform permissions.

## Configuration

```json
{
  "BaseUrl": "https://auth.example.com/bridge"
}
```

`OAuth2BridgeOptions` contains only `BaseUrl`. Platform API URLs are constants owned by each adapter. Pass `scope` in the authorization request; application credentials are supplied in the token request.

`BaseUrl` is a required root-level setting for the externally visible service base URL, excluding the provider suffix. Set it through `appsettings.json` or the `BaseUrl` environment variable. It must be an absolute HTTP(S) URL without credentials, query parameters, or a fragment. Missing or invalid configuration fails at startup.

The configured URL is used only to generate metadata URLs, preserving its path and removing the trailing slash before appending a provider. It is never inferred from request URLs, host headers, or forwarded headers, and it does not change application routing. For `BaseUrl=https://auth.example.com/subroute`, metadata advertises `https://auth.example.com/subroute/feishu/token`; the front proxy must strip `/subroute` and forward to `/feishu/token`. Forwarding `/subroute/feishu/token` directly returns HTTP 404.

## Run and test

```bash
dotnet run --project Src/OAuth2Bridge/OAuth2Bridge.csproj -- --BaseUrl=http://localhost:5292
dotnet test OAuth2Bridge.slnx --configuration Release
```

The default development HTTP URL is `http://localhost:5292`. On this local machine, invoke all `dotnet` commands with elevated permissions.

Tests cover provider discovery and routing, removal of legacy endpoints, authorization parameter forwarding, both platforms' token exchange and user claims, and upstream failures. Upstream HTTP calls are stubbed; real platform sign-in requires application credentials and registered callbacks.

## Container and CI

```text
ghcr.io/xmmshp/oauth2-bridge:latest
```

```bash
docker run -d --name oauth2-bridge -p 8080:80 \
  -e BaseUrl=https://auth.example.com \
  ghcr.io/xmmshp/oauth2-bridge:latest
```

GitHub Actions builds and tests pull requests and pushes to `main`. Pushes to `main` and `v*` tags publish the repository-named GHCR image with branch/tag, commit SHA, and default-branch `latest` tags. The renamed image becomes available after a successful publish workflow; the old GHCR package is separate.

## Platform references

- [DingTalk login documentation](https://open.dingtalk.com/document/orgapp/obtain-identity-credentials)
- [Feishu authorization code](https://open.feishu.cn/document/authentication-management/access-token/obtain-oauth-code)
- [Feishu v3 user access token](https://open.feishu.cn/document/authentication-management/access-token/get-user-access-token-v3)
- [Feishu user information](https://open.feishu.cn/document/server-docs/authentication-management/login-state-management/get)
