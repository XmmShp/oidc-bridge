# oauth2-bridge

`oauth2-bridge` converts platform-specific OAuth capabilities into a consistent OAuth 2.0 authorization-code interface. It is an ASP.NET Core (`net10.0`) service for clients such as identity brokers and web applications.

Adapters support **DingTalk, Feishu, GitHub, Gitee, QQ, Weibo, WeChat website login, and WeChat Official Account web authorization**. Clients use the same authorization, token, discovery, and user information interface for each adapter. Platforms that already provide standard OAuth/OIDC with discovery are listed for direct integration instead of being proxied.

## Architecture

```text
OAuth client → shared OAuth endpoints → IOAuthProvider
                                       ├── DingTalk / Feishu
                                       ├── GitHub / Gitee / Weibo / QQ
                                       └── WeChat website / Official Account
```

- `OAuthEndpoints` owns routing, common request validation, client authentication parsing, and OAuth responses.
- `OAuthProviderRegistry` resolves the adapter by the required provider name in the URL.
- Each `IOAuthProvider` implementation owns platform authorization parameters, token exchange, upstream errors, and user claim normalization.
- All adapters call OpenAPI directly using typed `HttpClient` instances with request cancellation support. `FormOAuthProvider` shares form-based OAuth mechanics; platform implementations own their endpoint and profile mappings.

To add a platform, implement `IOAuthProvider` and register it with dependency injection. Shared endpoints discover the registration without new platform-specific routes or conditionals.

## Endpoints

Replace `{provider}` with one of the adapter names below:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/` | Bridge adapters in `providers`, plus official discovery links in `direct_providers` |
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

Use the selected platform's application ID/key and application secret as `client_id`/`client_secret`. Token requests support `client_secret_basic` and `client_secret_post`; the bridge converts these to the platform's expected request format. Credentials are not stored in service configuration. New adapters require the original `redirect_uri` in the token request.

There is no bridge callback or independent client registration. Register the downstream client's callback URL in the platform console. Authorization-code validation, token lifetime, and application permissions are enforced by the platform. Tokens are upstream tokens except for the encrypted WeChat envelope described below. Only `authorization_code` is supported; refresh-token grants are not implemented, even when the upstream response includes a refresh token. When the upstream does not provide a token lifetime, `expires_in` is omitted rather than invented.

## Platform selection

The following public authorization-code flows need bridging because discovery is missing or their parameter/token/userinfo contracts need translation. Endpoint selection is fixed in each implementation; caller-supplied upstream hosts are not accepted.

| Adapter | Application type | Default native scope | Stable `sub` |
| --- | --- | --- | --- |
| `dingtalk` | DingTalk OAuth application | `openid` | `unionId` |
| `feishu` | Feishu OAuth application | No scope parameter | `open_id` |
| `github` | GitHub.com OAuth App | `read:user` | Numeric account `id` as a string |
| `gitee` | Gitee.com OAuth application | `user_info` | Numeric account `id` as a string |
| `qq` | QQ Connect website application | `get_user_info` | Application-scoped `openid` |
| `weibo` | Weibo website OAuth application | No scope parameter | Account `uid` as a string |
| `wechat` | WeChat Open Platform website application | `snsapi_login` | Application-scoped `openid` |
| `wechat-mp` | WeChat Official Account web authorization | `snsapi_userinfo` | Application-scoped `openid` |

Scopes use platform-native permission names. The bridge accepts space-separated scope lists and translates to commas for QQ and Weibo. Website and Official Account WeChat credentials/scopes belong to different application types and must not be mixed. There is no client-side JSAPI, mini-program login, or enterprise auto-login flow in these adapters.

The following providers already have official discovery endpoints and **do not get bridge routes**:

| Platform | Official discovery URL |
| --- | --- |
| GitLab.com | [Discovery](https://gitlab.com/.well-known/openid-configuration) |
| Google / Workspace | [Discovery](https://accounts.google.com/.well-known/openid-configuration) |
| Microsoft / Entra ID / Microsoft 365 | [Discovery](https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration) |
| Slack Sign in with Slack | [Discovery](https://slack.com/.well-known/openid-configuration) |
| LinkedIn | [Discovery](https://www.linkedin.com/oauth/.well-known/openid-configuration) |
| Discord | [Discovery](https://discord.com/.well-known/openid-configuration) |
| Sign in with Apple | [Discovery](https://appleid.apple.com/.well-known/openid-configuration) |

GitLab Self-Managed publishes `https://<your-instance>/.well-known/openid-configuration`; enable the application's `openid` scope. For Microsoft, select the tenant-specific discovery document when appropriate. Provider registration, enabled products/scopes, and account or tenant restrictions still apply. GitHub Actions' workload OIDC issuer is unrelated to GitHub user OAuth login.

### Platform differences

- **DingTalk:** calls `POST /v1.0/oauth2/userAccessToken` with camelCase JSON fields and `GET /v1.0/contact/users/me` with the `x-acs-dingtalk-access-token` header. Authorization redirects always include `prompt=consent`. The authorization request supplies `scope`, defaulting to `openid` when omitted. PKCE authorization requests are rejected because this adapter does not support PKCE.
- **Feishu:** uses the current v3 token endpoint, with JSON request translation. The authorization request supplies `scope` using Feishu permission names; when omitted, the parameter is left out. `code_challenge`, `code_challenge_method`, `code_verifier`, and `prompt` are forwarded. The platform validates PKCE and callback matching.

DingTalk and Feishu return `sub`, `name`, `picture`, `email`, and `phone_number` when available. DingTalk preserves its existing extra fields and raw `dingtalk` object. Feishu returns `open_id`, `union_id`, `user_id`, and raw `feishu` data. Feishu `sub` consistently uses the application-scoped `open_id`. Optional profile fields depend on platform permissions.

- **GitHub / Gitee:** use public profile fields, with `login` as the display-name fallback. GitHub requests JSON token responses and supports `S256` PKCE. The GitHub `/user` API only returns public email; this adapter does not fetch private email addresses or claim they are verified. GitHub may omit `expires_in` for non-expiring tokens.
- **QQ:** translates token exchange to GET with `fmt=json`, translates scope separators, resolves `openid` and the application ID through `/oauth2.0/me`, then calls `get_user_info`. `state` is required.
- **Weibo:** normalizes the token response; `/userinfo` queries the token owner before fetching that user's profile. Large IDs stay strings and display names never become subjects.
- **WeChat:** translates `client_id`/`client_secret` to `appid`/`secret`. Because upstream userinfo requires both `access_token` and `openid`, the returned bearer token is an authenticated, encrypted envelope containing that pair and the upstream expiry. Send it only to this bridge's `/userinfo`; it is not a raw token for calling WeChat APIs. `snsapi_base` returns an identity-only profile after checking upstream token validity. A token remains usable for repeated userinfo requests until expiry.

The new adapters reject PKCE requests when that upstream flow has not been implemented with PKCE; they do not silently discard a challenge or verifier. Upstream transport failures, rate limits, and malformed responses produce 502; rejected tokens produce a bearer challenge. Upstream error bodies are not returned to clients. HTTP client URL logging is disabled for new adapters because some native APIs require tokens or application secrets in their query string.

WeChat envelopes use ASP.NET Core Data Protection. Persist and share the key ring across container restarts and replicas so issued envelopes remain readable. In the current root-user Docker image, mount `/root/.aspnet/DataProtection-Keys`. Without persistent keys, restarting/replacing a container can invalidate outstanding WeChat bridge tokens. Other adapters continue passing upstream tokens through.

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

Tests cover adapter discovery and routing, direct-integration listings, removal of legacy endpoints, authorization parameter forwarding, platform token exchange and user claims, upstream failures, and WeChat envelope tampering/expiry. Upstream HTTP calls are stubbed; real platform sign-in requires application credentials and registered callbacks. No live account login is claimed by these tests.

## Container and CI

```text
ghcr.io/xmmshp/oauth2-bridge:latest
```

```bash
docker run -d --name oauth2-bridge -p 8080:80 \
  -e BaseUrl=https://auth.example.com \
  -v oauth2-bridge-keys:/root/.aspnet/DataProtection-Keys \
  ghcr.io/xmmshp/oauth2-bridge:latest
```

GitHub Actions builds and tests pull requests and pushes to `main`. Pushes to `main` and `v*` tags publish the repository-named GHCR image with branch/tag, commit SHA, and default-branch `latest` tags. The renamed image becomes available after a successful publish workflow; the old GHCR package is separate.

## Platform references

- [DingTalk login documentation](https://open.dingtalk.com/document/orgapp/obtain-identity-credentials)
- [Feishu authorization code](https://open.feishu.cn/document/authentication-management/access-token/obtain-oauth-code)
- [Feishu v3 user access token](https://open.feishu.cn/document/authentication-management/access-token/get-user-access-token-v3)
- [Feishu user information](https://open.feishu.cn/document/server-docs/authentication-management/login-state-management/get)
- [GitHub OAuth Apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
- [Gitee OAuth documentation](https://gitee.com/api/v5/oauth_doc) and [OpenAPI schema](https://gitee.com/api/v5/swagger_doc.json)
- [QQ authorization-code flow](https://wiki.connect.qq.com/使用authorization_code获取access_token), [OpenID](https://wiki.connect.qq.com/获取用户openid_oauth2-0), and [user information](https://wiki.connect.qq.com/get_user_info)
- [Weibo OAuth](https://open.weibo.com/wiki/Oauth2/authorize), [token owner](https://open.weibo.com/wiki/Oauth2/get_token_info), and [profile](https://open.weibo.com/wiki/2/users/show)
- [WeChat website login](https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html) and [Official Account web authorization](https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html)
- [GitLab OIDC discovery](https://docs.gitlab.com/integration/openid_connect_provider/)
