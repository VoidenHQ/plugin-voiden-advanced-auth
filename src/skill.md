## Extension: Voiden Advanced Auth

Provides the `auth` block for all authentication types. Place it inside or alongside a `request` block.

> **Singleton per section — one `auth` block total, no matter the type.** `bearer`, `basic`, `apiKey`, `oauth1`, `oauth2`, `digest`, `awsSignature`, `ntlm`, `hawk`, `netrc`, `atlassianAsap`, and `inherit`/`none` all fill the *same* single `auth` slot in a section. Changing auth type means editing this one block's `authType` and fields in place — never insert a second `auth` block alongside the first.

### auth — Authentication Block

```yaml
---
type: auth
attrs:
  uid: "uid"
  authType: bearer      # see types below
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [token, "{{API_TOKEN}}"]
---
```

### Choosing the auth block when generating requests for an API

This applies whenever you generate `.void` requests for an API, whatever the source: a codebase, a running server, an OpenAPI document, or an imported collection. Decide the auth block from **what the protected endpoints accept**, not from how the API's login is implemented.

| What the protected endpoints check | Use |
|---|---|
| `Authorization: Bearer <token>`, and the token comes from an OAuth 2.0 token endpoint (the API's own, or a provider's such as Google or Auth0) | `authType: oauth2` on each protected request |
| `Authorization: Bearer <token>`, where the token is a static key or comes from a non-OAuth login endpoint | `authType: bearer`, with the token in an environment variable or captured from the login request as `{{process.token}}` |
| An API key in a header or query parameter | `authType: apiKey` |
| A **session cookie** set by the server after a browser login (including "Sign in with Google/GitHub" handled by the server) | No `auth` block. See "Cookie sessions" below |

How to recognise each case in a codebase:

- **The API is, or delegates to, an OAuth 2.0 server.** Look for a token endpoint that accepts `grant_type` and returns `access_token` (often `/oauth/token`), an authorization endpoint (`/oauth/authorize`), `/.well-known/oauth-authorization-server` or `/.well-known/openid-configuration`, an `oauth2` entry under an OpenAPI document's `securitySchemes`, or middleware that reads `Authorization: Bearer` and checks scopes. **Put an `oauth2` auth block on the protected requests.** Do not model the login as plain requests to `/oauth/authorize` and `/oauth/token`: the authorize endpoint is a browser page that a request cannot complete, and the block already performs both steps.
- **Cookie sessions.** Look for the server redirecting to a provider, handling the callback itself with its own client secret, and then calling `Set-Cookie`; protected handlers read `req.cookies`/a session, never an `Authorization` header. Here the server is the OAuth client and the API never accepts a token, so an `oauth2` block would obtain a token the API ignores. Generate the login endpoints as plain requests with `follow_redirects` set to `false` in an `options-table` (assert the `302` and its `Location`; following the redirect lands on the provider's sign-in page, which rejects non-browser clients), and send the session cookie on protected requests with a `cookies-table` holding an environment variable. Say in the file that the cookie has to be copied from a signed-in browser.

Pick the OAuth grant from what the server offers to a client like Voiden:

- `client_credentials` when a confidential client (id + secret) exists for machine access. Prefer it for test suites: it needs no browser.
- `authorization_code` when requests must act as a signed-in user. Use a client the server registers for native/public use, and check its allowed redirect URIs (see "Callback URL" below).
- `password` only if the server still supports it. `implicit` only if nothing else is offered.

### Auth Types

#### inherit / none

```yaml
attrs:
  authType: inherit   # use parent/collection auth
# or
  authType: none      # no authentication
content: []
```

#### bearer — Bearer Token

```yaml
attrs:
  authType: bearer
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [token, "{{API_TOKEN}}"]
```
Sends: `Authorization: Bearer <token>`

#### basic — Username + Password

```yaml
attrs:
  authType: basic
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [username, "{{API_USERNAME}}"]
      - attrs: { disabled: false }
        row: [password, "{{API_PASSWORD}}"]
```
Sends: `Authorization: Basic <base64(user:pass)>`

#### apiKey — API Key

```yaml
attrs:
  authType: apiKey
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [key, X-API-Key]
      - attrs: { disabled: false }
        row: [value, "{{API_KEY}}"]
      - attrs: { disabled: false }
        row: [add_to, header]   # header or query
```

#### oauth2 — OAuth 2.0

In the app, an `oauth2` block obtains an access token (opening the system browser when the grant needs a sign-in), stores it in runtime variables, and adds it to the request. The block's settings live in two places, and both must be written:

| Where | Holds |
|---|---|
| Table rows (2 columns: key, value) | The values the flow uses: `auth_url`, `token_url`, `client_id`, `client_secret`, `scope`, `callback_url`, `state`, `username`, `password`. Which rows apply depends on the grant type (shown below). `{{ENV_VAR}}` references are resolved here |
| `oauth2Config` attribute (a JSON string) | The behaviour: `grantType`, `addTokenTo` (`header` or `query`), `headerPrefix` (default `Bearer`), `clientAuthMethod`, `autoRefresh`, `variablePrefix` (default `oauth2`), `customParams` |

- `grantType` is read **only** from `oauth2Config`. If it is missing the block runs as `authorization_code`, whatever rows are present.
- `clientAuthMethod` is `client_secret_post` (default; credentials in the form body) or `client_secret_basic` (credentials in an `Authorization: Basic` header). No other value is recognised.
- `autoRefresh` must be the JSON boolean `true` to refresh an expired token with the stored refresh token.
- The token is stored as `{{process.<variablePrefix>_access_token}}` (so `{{process.oauth2_access_token}}` by default), with `_token_type`, `_refresh_token` and `_expires_at` alongside. Give two blocks different `variablePrefix` values if they must hold different tokens.

**authorization_code** — a user signs in through the system browser. PKCE (`S256`) is always sent; there is no setting for it, and a server that requires PKCE works as is. Leave `client_secret` out for a public client.

*Callback URL.* Voiden receives the redirect on a local listener. With no `callback_url` row it uses `http://127.0.0.1:<random port>/callback`, which a server that requires an exact registered redirect URI will reject. For such a server set `callback_url` to a fixed address, for example `http://127.0.0.1:53682/callback`, and register that exact address on the authorization server for the client being used. If the server cannot be changed, this grant cannot be used with it.

```yaml
attrs:
  authType: oauth2
  oauth2Config: '{"grantType":"authorization_code","addTokenTo":"header","headerPrefix":"Bearer","clientAuthMethod":"client_secret_post","autoRefresh":true,"variablePrefix":"oauth2"}'
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [auth_url, "{{OAUTH_AUTH_URL}}"]
      - attrs: { disabled: false }
        row: [token_url, "{{OAUTH_TOKEN_URL}}"]
      - attrs: { disabled: false }
        row: [client_id, "{{OAUTH_CLIENT_ID}}"]
      - attrs: { disabled: false }
        row: [client_secret, "{{OAUTH_CLIENT_SECRET}}"]
      - attrs: { disabled: false }
        row: [scope, "read write"]
      - attrs: { disabled: false }
        row: [callback_url, "{{OAUTH_CALLBACK_URL}}"]
      - attrs: { disabled: false }
        row: [state, "{{OAUTH_STATE}}"]
```

**implicit** — no client secret, token returned directly from auth endpoint:

```yaml
attrs:
  authType: oauth2
  oauth2Config: '{"grantType":"implicit","addTokenTo":"header","headerPrefix":"Bearer","variablePrefix":"oauth2"}'
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [auth_url, "{{OAUTH_AUTH_URL}}"]
      - attrs: { disabled: false }
        row: [client_id, "{{OAUTH_CLIENT_ID}}"]
      - attrs: { disabled: false }
        row: [scope, "read"]
      - attrs: { disabled: false }
        row: [callback_url, "{{OAUTH_CALLBACK_URL}}"]
      - attrs: { disabled: false }
        row: [state, "{{OAUTH_STATE}}"]
```

**password** — resource owner password credentials:

```yaml
attrs:
  authType: oauth2
  oauth2Config: '{"grantType":"password","addTokenTo":"header","headerPrefix":"Bearer","clientAuthMethod":"client_secret_post","variablePrefix":"oauth2"}'
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [token_url, "{{OAUTH_TOKEN_URL}}"]
      - attrs: { disabled: false }
        row: [client_id, "{{OAUTH_CLIENT_ID}}"]
      - attrs: { disabled: false }
        row: [client_secret, "{{OAUTH_CLIENT_SECRET}}"]
      - attrs: { disabled: false }
        row: [username, "{{OAUTH_USERNAME}}"]
      - attrs: { disabled: false }
        row: [password, "{{OAUTH_PASSWORD}}"]
      - attrs: { disabled: false }
        row: [scope, "read write"]
```

**client_credentials** — machine-to-machine, no user context:

```yaml
attrs:
  authType: oauth2
  oauth2Config: '{"grantType":"client_credentials","addTokenTo":"header","headerPrefix":"Bearer","clientAuthMethod":"client_secret_basic","variablePrefix":"oauth2"}'
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [token_url, "{{OAUTH_TOKEN_URL}}"]
      - attrs: { disabled: false }
        row: [client_id, "{{OAUTH_CLIENT_ID}}"]
      - attrs: { disabled: false }
        row: [client_secret, "{{OAUTH_CLIENT_SECRET}}"]
      - attrs: { disabled: false }
        row: [scope, "api"]
```

**The `oauth2` block only runs in the Voiden app.** `voiden-runner` and the `voiden-mcp` tools apply `bearer`, `basic` and `apiKey` blocks headlessly, but skip `oauth2` (and `oauth1`, `digest`, `ntlm`, `awsSignature`): a request carrying one is sent with no credentials there. So:

- Do not expect to verify an `oauth2` request with `run_request`; a `401` from a headless run does not mean the block is wrong. Tell the user to press **Get Token** in the app.
- For files meant to run unattended (CI, `voiden-runner`, an agent verifying its own output), get the token with an ordinary request instead, which is only possible for grants with no browser step:

```void
---
type: request
attrs:
  uid: "uid"
content:
  - type: method
    attrs: { uid: "uid", method: POST, visible: true }
    content: POST
  - type: url
    attrs: { uid: "uid" }
    content: "{{BASE_URL}}/oauth/token"
---
```

```void
---
type: url-table
attrs:
  uid: "uid"
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [grant_type, client_credentials, "—"]
      - attrs: { disabled: false }
        row: [client_id, "{{OAUTH_CLIENT_ID}}", "—"]
      - attrs: { disabled: false }
        row: [client_secret, "{{OAUTH_CLIENT_SECRET}}", "—"]
      - attrs: { disabled: false }
        row: [scope, "api", "—"]
---
```

```void
---
type: runtime-variables
attrs:
  uid: "uid"
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [access_token, "{{$res.body.access_token}}", "Used by the sections below"]
---
```

Later sections then use `authType: bearer` with `[token, "{{process.access_token}}"]`. When a project needs both, generate both: the token-request file for automated runs, and a file with the `oauth2` block for interactive use.

#### oauth1 — OAuth 1.0a

```yaml
attrs:
  authType: oauth1
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [consumer_key, "{{CONSUMER_KEY}}"]
      - attrs: { disabled: false }
        row: [consumer_secret, "{{CONSUMER_SECRET}}"]
      - attrs: { disabled: false }
        row: [access_token, "{{ACCESS_TOKEN}}"]
      - attrs: { disabled: false }
        row: [token_secret, "{{TOKEN_SECRET}}"]
      - attrs: { disabled: false }
        row: [signature_method, HMAC-SHA1]   # HMAC-SHA1, HMAC-SHA256, PLAINTEXT
```

#### digest — HTTP Digest

```yaml
attrs:
  authType: digest
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [username, "{{USERNAME}}"]
      - attrs: { disabled: false }
        row: [password, "{{PASSWORD}}"]
```

#### awsSignature — AWS Signature v4

```yaml
attrs:
  authType: awsSignature
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [access_key, "{{AWS_ACCESS_KEY}}"]
      - attrs: { disabled: false }
        row: [secret_key, "{{AWS_SECRET_KEY}}"]
      - attrs: { disabled: false }
        row: [region, us-east-1]
      - attrs: { disabled: false }
        row: [service, execute-api]
      - attrs: { disabled: false }
        row: [session_token, "{{AWS_SESSION_TOKEN}}"]   # optional
```

#### ntlm — NTLM

```yaml
attrs:
  authType: ntlm
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [username, "DOMAIN\\user"]
      - attrs: { disabled: false }
        row: [password, "{{PASSWORD}}"]
      - attrs: { disabled: false }
        row: [domain, MYDOMAIN]
      - attrs: { disabled: false }
        row: [workstation, my-pc]
```

#### hawk — Hawk

```yaml
attrs:
  authType: hawk
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [id, "{{HAWK_ID}}"]
      - attrs: { disabled: false }
        row: [key, "{{HAWK_KEY}}"]
      - attrs: { disabled: false }
        row: [algorithm, sha256]
```

#### netrc

```yaml
attrs:
  authType: netrc
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [machine, api.example.com]
      - attrs: { disabled: false }
        row: [login, "{{USERNAME}}"]
      - attrs: { disabled: false }
        row: [password, "{{PASSWORD}}"]
```

#### atlassianAsap — Atlassian ASAP

```yaml
attrs:
  authType: atlassianAsap
content:
  - type: table
    rows:
      - attrs: { disabled: false }
        row: [issuer, "{{ASAP_ISSUER}}"]
      - attrs: { disabled: false }
        row: [subject, "{{ASAP_SUBJECT}}"]
      - attrs: { disabled: false }
        row: [audience, "{{ASAP_AUDIENCE}}"]
      - attrs: { disabled: false }
        row: [key_id, "{{ASAP_KEY_ID}}"]
      - attrs: { disabled: false }
        row: [private_key, "{{ASAP_PRIVATE_KEY}}"]
```

### Auth Field Reference

| `authType` | Required rows | Optional rows |
|------------|--------------|---------------|
| `inherit` / `none` | — | — |
| `bearer` | `token` | — |
| `basic` | `username`, `password` | — |
| `apiKey` | `key`, `value`, `add_to` | — |
| `oauth2` (authorization_code) | `auth_url`, `token_url`, `client_id`, `client_secret`, `scope`, `callback_url` | `state` |
| `oauth2` (implicit) | `auth_url`, `client_id`, `scope`, `callback_url` | `state` |
| `oauth2` (password) | `token_url`, `client_id`, `client_secret`, `username`, `password` | `scope` |
| `oauth2` (client_credentials) | `token_url`, `client_id`, `client_secret` | `scope` |
| `oauth1` | `consumer_key`, `consumer_secret`, `access_token`, `token_secret` | `signature_method` |
| `digest` | `username`, `password` | — |
| `awsSignature` | `access_key`, `secret_key`, `region`, `service` | `session_token` |
| `ntlm` | `username`, `password` | `domain`, `workstation` |
| `hawk` | `id`, `key` | `algorithm` |
| `netrc` | `machine`, `login`, `password` | — |
| `atlassianAsap` | `issuer`, `subject`, `audience`, `key_id`, `private_key` | — |

**Always use `{{VARIABLE_NAME}}` for credentials — never hardcode secrets in `.void` files.**
