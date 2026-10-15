# oidc-bridge

`oidc-bridge` turns platform OAuth login into an OpenID Connect authorization-code interface. OIDC is the service's core protocol: each adapter exposes discovery, authorization, token, userinfo, and JWKS endpoints. It is an ASP.NET Core (`net10.0`) service for identity brokers and web applications.

Adapters support **DingTalk, Feishu, GitHub, Gitee, QQ, and Weibo** using OpenAPI directly, without platform SDKs. Platforms with their own standard OIDC discovery should be integrated directly.

The service is stateless at runtime. It does not store login sessions, authorization codes, user profiles, or tokens, and requires no database, cache, persistent volume, or sticky sessions. All instances derive the same RSA key from the same configured `SigningKey` string. Encrypted tickets and short-lived browser correlation cookies carry the authorization context; userinfo fetches the platform profile on each request.

## Configuration

All settings use the standard .NET configuration system at the root. `BaseUrl`, `SigningKey`, and `Clients` can all be configured in `appsettings.json`:

```json
{
  "BaseUrl": "https://auth.example.com/subroute",
  "SigningKey": "a-long-random-secret-string-kept-identical-on-all-instances",
  "Clients": [
    {
      "Provider": "dingtalk",
      "ClientId": "your-platform-app-id",
      "RedirectUris": ["https://client.example.com/oidc/callback"]
    },
    {
      "Provider": "feishu",
      "ClientId": "your-feishu-app-id",
      "RedirectUris": ["https://client.example.com/oidc/callback"],
      "UpstreamScope": "contact:user.base:readonly"
    }
  ]
}
```

- `BaseUrl` is the required external service base URL, excluding the provider suffix. Production OIDC URLs require HTTPS; HTTP loopback is allowed for local development. Credentials, queries, and fragments are rejected.
- `SigningKey` is a required non-empty secret string, not a PEM or encoded RSA key. Unicode, whitespace, and punctuation are supported. Input is exact UTF-8: it is not trimmed or Unicode-normalized. A long random value is recommended: someone who guesses this string can reconstruct the private key. Environment variables or a secret manager can keep production secrets out of configuration files.
- `Clients` is the reloadable allowlist of provider/application IDs and exact downstream redirect URIs. Client secrets are not stored. The list may be empty for discovery-only deployment; authorization requires a registered entry. Duplicate provider/client pairs and invalid redirect URIs fail startup.
- `UpstreamScope` contains native platform permissions. When omitted, the adapter uses its default. OIDC scopes are separate and are never forwarded as native platform permissions.

The platform's app ID and app secret remain the downstream OIDC client's `client_id` and `client_secret`. OIDC is always enabled; there is no optional OAuth-only deployment mode or PEM configuration.

The framework's normal configuration precedence is preserved: environment variables override JSON values, and command-line arguments override environment variables. Environment-specific JSON files also retain their normal precedence. For example, these optional overrides replace the corresponding values from `appsettings.json`:

```bash
export BaseUrl=https://auth.example.com/subroute
export SigningKey='a-long-random-secret-string-kept-identical-on-all-instances'
```

Configuration source and reload policy are separate: `BaseUrl` and `SigningKey` are captured at startup from the merged .NET configuration, regardless of which source supplied them. Only `Clients` is applied dynamically.

### Updating clients without restarting

The service watches the standard JSON configuration files. Edit the root `Clients` array in `appsettings.json`; new requests use the complete validated replacement list after the file change is detected. Adding clients, changing callback allowlists or native scopes, and removing clients require no restart. Use a single JSON source for `Clients`: environment variables and environment-specific configuration files take precedence and can otherwise preserve or override entries from another file.

Startup configuration must be valid. After startup, malformed JSON and invalid client lists are rejected with a warning, and the last valid client configuration stays active. Correcting the file applies the next valid update automatically. An explicit `"Clients": []` removes all registrations. Write a complete file and replace it atomically when possible, instead of exposing intermediate edits.

Authorization, callback, token, and userinfo processing each consult the latest client list. Removing a client blocks subsequent bridge operations, including userinfo with a previously issued wrapped access token. Removing a redirect URI also prevents pending callbacks and code exchanges for that URI. Native scope updates affect future authorizations. Already issued ID Tokens remain verifiable until expiry; configuration reload is not token revocation at downstream applications.

`BaseUrl` and the derived signing key are fixed for the process lifetime. Client reload does not change the issuer, regenerate keys, or invalidate tickets for unchanged clients. Changes to their effective configuration values require restarting the instance, whether those values come from JSON, environment variables, or another standard configuration source.

The last valid client snapshot is deployment configuration held in memory, not per-user state. Instances still have no database, shared cache, persisted sessions, or token/code storage. Roll out the same client configuration to every replica; each instance watches and validates its own mounted file.

### Stable key derivation

Derivation **v1** is fixed:

1. PBKDF2-HMAC-SHA512, 210,000 iterations, salt `oidc-bridge/key-derivation/v1`, 64 output bytes.
2. HMAC-DRBG-SHA512 with the first 48 bytes as its entropy input, the remaining 16 bytes as its nonce, security strength 256, personalization `oidc-bridge/rsa-2048/v1`, and no prediction-resistant reseeding.
3. Bouncy Castle RSA-2048 generation with exponent 65537 and certainty 128. The dependency version is pinned, and a fixed public-key test vector guards against generation changes during upgrades.

The derived key signs RS256 ID Tokens and protects transaction/code/access-token envelopes. JWKS exposes only the public RSA parameters and a stable key ID. Derivation is performed once at startup per instance and does not depend on host, OS, issuer URL, time, or random startup values. The deterministic DRBG is used only for deriving this key; correlation values and ticket encryption still use fresh cryptographic randomness.

Changing `SigningKey` changes the key pair and invalidates in-flight tickets and wrapped access tokens. Deploy changes consistently across replicas. The initial implementation has one active key and does not provide overlapping key rotation, per-token revocation, or local replay tracking. Do not alter v1 parameters without a key migration.

### Reverse proxy paths

`BaseUrl` generates metadata, issuer, and public callback URLs. Its path is preserved and trailing slashes are removed before appending the provider. It is never inferred from request URLs, Host, or forwarded headers, and it does not change routing.

For `BaseUrl=https://auth.example.com/subroute`, the service advertises `https://auth.example.com/subroute/feishu/token`. The proxy must strip `/subroute` and forward to `/feishu/token`. The same applies to discovery, JWKS, and callback routes. Forwarding `/subroute/feishu/token` directly returns HTTP 404.

## Endpoints

Each provider has an issuer `{BaseUrl}/{provider}`:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/` | Adapter OIDC discovery links and official direct-integration discovery links |
| GET | `/{provider}/.well-known/openid-configuration` | Primary OIDC discovery |
| GET | `/{provider}/jwks` | Public signing key |
| GET | `/{provider}/authorize` | Begin OIDC authorization |
| GET | `/{provider}/callback` | Platform callback to the bridge |
| POST | `/{provider}/token` | Redeem a bridge authorization code and obtain an ID Token |
| GET / POST | `/{provider}/userinfo` | Scope-filtered claims using a bearer authorization header |
| GET | `/{provider}/.well-known/oauth-authorization-server` | OAuth metadata alias describing the same OIDC flow |
| GET | `/.well-known/oauth-authorization-server/{provider}` | RFC 8414 metadata alias |

An explicit provider is required. Unprefixed authorization/token/userinfo/discovery routes and unknown providers return HTTP 404. The old native OAuth passthrough flow is removed: raw platform codes and access tokens cannot be used directly at bridge endpoints.

## Authorization flow

1. Register `{BaseUrl}/{provider}/callback` in the platform console, and register the downstream callback in `Clients`.
2. Configure the downstream client with issuer `{BaseUrl}/{provider}`. Discovery is `{issuer}/.well-known/openid-configuration`.
3. Send `response_type=code`, a registered `client_id` and `redirect_uri`, `scope=openid profile email`, and normally `state`, `nonce`, and S256 PKCE. The bridge validates the exact client/callback pair before redirecting. Supported OIDC scopes are `openid`, `profile`, `email`, and `phone`; `openid` is required.
4. The platform returns to the bridge callback. A signed/encrypted 10-minute transaction ticket and an HttpOnly, SameSite=Lax cookie bind the browser to the request. The cookie uses the public callback path, is Secure for HTTPS, and is deleted on completion. Each parallel login attempt has a separate cookie. There is no server-side login session.
5. The bridge redirects to the downstream callback with the original `state`, `iss`, and a signed/encrypted code valid for two minutes. The downstream sends a form-encoded token request with its platform credentials, original downstream `redirect_uri`, and PKCE verifier if supplied. `client_secret_basic` and `client_secret_post` are supported.
6. The bridge redeems the original upstream code only at token exchange, with its own callback URI and independent upstream PKCE where supported. Upstream one-time code redemption protects against reuse across bridge instances. It fetches the profile and issues a five-minute RS256 ID Token containing `iss`, `sub`, `aud`, `iat`, `exp`, `at_hash`, and the original `nonce` when supplied.
7. The OIDC access token is an encrypted/signed envelope containing the native access token, client ID, subject, and granted scopes. It expires at the earlier of one hour and the upstream lifetime, or one hour if no upstream lifetime is given. Userinfo unwraps it, fetches the profile, checks subject consistency, and filters claims by scope. Raw platform objects and unrequested profile/email/phone claims are not exposed.

Any instance with the same `SigningKey`, `BaseUrl`, and client configuration can handle any step. If the platform has consumed a code and a later step fails, restart login. Bridge codes are not locally stored or marked consumed; code reuse is rejected by the platform.

### Protocol scope and upstream limitations

The service implements the OIDC authorization-code flow for confidential clients. It does not implement implicit/hybrid flows, public clients, refresh/offline access, dynamic registration, request objects, the `claims` request parameter, or logout/session management. No OpenID conformance certification is claimed.

The bridge has no SSO session, so `prompt=none` returns `login_required`. Native OAuth does not reliably attest authentication age or force fresh authentication: `prompt=login` and valid `max_age` requests return `login_required`, and no `auth_time` is invented. `prompt=select_account` returns `account_selection_required`. Explicit `prompt=consent` is supported for DingTalk/Feishu and returns `consent_required` for other adapters. Display/locales/ACR preferences are best-effort hints and do not cause an error.

See [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html), and [Bouncy Castle's C# documentation](https://www.bouncycastle.org/documentation/documentation-c/).

## Platform adapters

| Adapter | Native authorization flow | Default native scope | Stable subject |
| --- | --- | --- | --- |
| `dingtalk` | DingTalk OAuth application | `openid` | `unionId` |
| `feishu` | Feishu OAuth application | No scope parameter | `open_id` |
| `github` | GitHub.com OAuth App | `read:user` | Numeric account ID as a string |
| `gitee` | Gitee.com OAuth application | `user_info` | Numeric account ID as a string |
| `qq` | QQ Connect website application | `get_user_info` | Application-scoped `openid` |
| `weibo` | Weibo website OAuth application | No scope parameter | Account `uid` as a string |

The protocol layer owns OIDC validation and issuance; `OAuthProviderRegistry` resolves `IOAuthProvider` adapters, which own native authorization parameters, token exchange, upstream errors, and normalized profiles. `FormOAuthProvider` shares form-based native OAuth mechanics. Adding an adapter requires its implementation and DI registration, with no platform-specific routing.

- **DingTalk:** JSON token exchange through `/v1.0/oauth2/userAccessToken`; profile through `/v1.0/contact/users/me` with `x-acs-dingtalk-access-token`. Authorization always includes `prompt=consent`. Downstream S256 PKCE is verified by the bridge; DingTalk does not receive an unsupported native PKCE challenge.
- **Feishu:** JSON token exchange, application-scoped `open_id`, and native PKCE independent of downstream PKCE. Native PKCE requests use `/open-apis/authen/v2/oauth/token` because the v3 endpoint rejects valid verifiers with error `20049` ([upstream report](https://github.com/larksuite/oapi-sdk-go/issues/230)); requests without native PKCE use v3. The endpoint is selected before redemption, with no fallback retry and no verifier removal. Optional profile permissions depend on the platform application's settings.
- **GitHub:** JSON token responses, native S256 PKCE, public profile and public email only. Private email is not fetched and verification is not asserted. Missing upstream token lifetime is preserved internally; the bridge access token still has its own bounded lifetime.
- **Gitee:** form token exchange and public profile normalization.
- **QQ:** GET token exchange with `fmt=json`; token-owner lookup supplies app ID and `openid` before fetching the profile. Native scope lists use commas.
- **Weibo:** token-owner lookup precedes profile retrieval; returned subject must match. Native scope lists use commas, and large IDs remain strings.

No JSAPI, mini-program, or enterprise silent-login flow is provided. WeChat website and Official Account adapters remain unsupported; `/wechat/*` and `/wechat-mp/*` return HTTP 404.

Upstream transport failures, rate limits, and malformed responses produce 502; rejected bearer tokens receive a challenge. Upstream error bodies are not returned. Typed HttpClients disable URL logging, cookie storage, and automatic redirects because some platform APIs require credentials in query parameters.

### Platforms to integrate directly

These platforms already publish their own OIDC discovery and do not get bridge routes:

| Platform | Official discovery |
| --- | --- |
| GitLab.com | [Discovery](https://gitlab.com/.well-known/openid-configuration) |
| Google / Workspace | [Discovery](https://accounts.google.com/.well-known/openid-configuration) |
| Microsoft / Entra ID / Microsoft 365 | [Discovery](https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration) |
| Slack Sign in with Slack | [Discovery](https://slack.com/.well-known/openid-configuration) |
| LinkedIn | [Discovery](https://www.linkedin.com/oauth/.well-known/openid-configuration) |
| Discord | [Discovery](https://discord.com/.well-known/openid-configuration) |
| Sign in with Apple | [Discovery](https://appleid.apple.com/.well-known/openid-configuration) |

GitLab Self-Managed uses `https://<your-instance>/.well-known/openid-configuration`. For Microsoft, use the tenant-specific issuer when appropriate. Platform application registration, products, scopes, and tenant restrictions still apply. GitHub Actions workload OIDC is unrelated to GitHub user login.

## Run, test, and deploy

```bash
# Configure SigningKey in appsettings.json or supply it through an environment variable.
dotnet run --project Src/OidcBridge/OidcBridge.csproj -- --BaseUrl=http://localhost:5292
dotnet test OidcBridge.slnx --configuration Release
```

The default local HTTP URL is `http://localhost:5292`. On this local machine all `dotnet` commands require elevated permissions. Tests cover adapter translation, OIDC endpoints and constraints, signature/nonce/PKCE, callback correlation, scope filtering, tampering, expiry, replay rejection by a stub upstream, cross-instance flows, deterministic key generation with fixed vectors, and real-file client reload with invalid-update recovery and stable issuer/JWKS. Actual platform login requires real credentials and callback registration; tests do not claim live sign-in coverage.

For hot updates in containers, prepare `./config/appsettings.json` with the `Clients` list above. Mount the whole configuration directory read-only so atomic file replacement remains visible, and use polling for filesystems that do not deliver change notifications reliably:

```bash
docker run -d --name oidc-bridge -p 8080:80 \
  -e BaseUrl=https://auth.example.com \
  -e SigningKey \
  -e DOTNET_USE_POLLING_FILE_WATCHER=1 \
  --mount type=bind,source="$(pwd)/config",target=/config,readonly \
  ghcr.io/xmmshp/oidc-bridge:latest --contentRoot /config
```

This example supplies `SigningKey` from the host environment. Alternatively, configure `BaseUrl` and `SigningKey` in the mounted JSON file and omit their corresponding `-e` flags. Updating the host file applies client changes within the watcher delay (typically a few seconds with polling). Environment variables themselves cannot hot reload. The service never writes to the mounted directory, and no persistent volume for runtime data is needed. GitHub Actions builds/tests the solution and publishes the repository-named GHCR image on pushes to `main` and `v*` tags. The renamed image is available after the first successful publish workflow; previously published packages remain separate.
