# dingtalk-oauth2

`dingtalk-oauth2` is a standard ASP.NET Core (`net10.0`) OAuth 2.0 bridge for DingTalk login.

It exposes a standard OAuth 2.0 authorization-code interface to downstream clients such as Keycloak, and uses the official AlibabaCloud DingTalk SDK to call DingTalk OAuth APIs.

Container image:

```text
ghcr.io/xmmshp/dingtalk-oauth2
```

## Endpoints

- `GET /.well-known/oauth-authorization-server`: OAuth 2.0 Authorization Server Metadata discovery endpoint.
- `GET /.well-known/openid-configuration`: OpenID Connect discovery-compatible metadata endpoint for clients that discover via the OIDC URL.
- `GET /authorize`: Standard OAuth 2.0 authorization endpoint. It redirects directly to DingTalk and keeps the client-provided `redirect_uri` and `state`.
- `POST /token`: Standard OAuth 2.0 token endpoint. It exchanges the DingTalk authorization code with DingTalk SDK.
- `GET /userinfo`: Standard bearer-token user info endpoint backed by DingTalk SDK. It returns standard claims and all fields from DingTalk `GetUserResponseBody`.

## Flow

1. The client redirects the browser to `/authorize?response_type=code&client_id=...&redirect_uri=...&state=...`.
2. The bridge returns an HTTP 302 redirect to DingTalk and passes `client_id`, `redirect_uri`, and `state` through.
3. DingTalk redirects the browser directly to the original client `redirect_uri` with `code` and `state`.
4. The client calls `/token` with `grant_type=authorization_code`, `code`, `client_id`, and `client_secret`.
5. The bridge passes `client_id` and `client_secret` to DingTalk SDK to exchange the DingTalk authorization code for a DingTalk user access token.
6. The client can call `/userinfo` with the returned bearer token to get normalized user claims.

This service does not host a `/callback` endpoint. The OAuth callback belongs to the client or identity broker, for example Keycloak's broker callback URL.

`/authorize` uses a browser redirect instead of a server-side proxy request. This is the standard OAuth 2.0 front-channel behavior: the user agent must visit the upstream authorization endpoint so the user can complete DingTalk login and consent.

## Configuration

Configure `OAuth2Bridge` in `appsettings.json` or environment variables:

```json
{
  "OAuth2Bridge": {
    "AuthorizeEndpoint": "https://login.dingtalk.com/oauth2/auth",
    "DingTalkScope": "openid"
  }
}
```

DingTalk `AppKey` and `AppSecret` are not configured in this service. Configure them as the upstream OAuth client's `client_id` and `client_secret`; the bridge passes them to DingTalk unchanged.

`issuer` in the discovery document is generated from the incoming request host. There is no issuer configuration item.

## Keycloak Notes

- Register this service as a generic OAuth 2.0 identity provider or client-facing authorization server.
- Use `{Issuer}/authorize` as the authorization URL.
- Use `{Issuer}/token` as the token URL.
- Use `{Issuer}/userinfo` as the user info URL.
- Configure DingTalk `AppKey` as the Keycloak client ID and DingTalk `AppSecret` as the Keycloak client secret.
- Configure the Keycloak callback URL as an allowed DingTalk callback URL.

## Local Run

```bash
dotnet run --project Src/DingtalkOAuth2/DingtalkOAuth2.csproj
```

Then open:

```text
http://localhost:5292/.well-known/oauth-authorization-server
```

## Tests

```bash
dotnet test DingtalkOAuth2.slnx
```

## CI/CD

GitHub Actions runs build and tests on pull requests and pushes to `main`.

On pushes to `main` and `v*` tags, it publishes Docker images to GHCR:

```text
ghcr.io/xmmshp/dingtalk-oauth2:latest
ghcr.io/xmmshp/dingtalk-oauth2:<branch-or-tag>
ghcr.io/xmmshp/dingtalk-oauth2:sha-<commit>
```
