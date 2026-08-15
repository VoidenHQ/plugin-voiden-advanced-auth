## Extension: Voiden Advanced Auth

Provides the `auth` block for all authentication types. Place it inside or alongside a `request` block.

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

OAuth2 rows depend on the grant type. The `oauth2Config` attribute (JSON string) stores the full OAuth2 configuration.

**authorization_code** — most common, requires redirect/callback:

```yaml
attrs:
  authType: oauth2
  oauth2Config: '{"grantType":"authorization_code","authUrl":"","tokenUrl":"","clientId":"","clientSecret":"","scope":"","callbackUrl":"","addTokenTo":"header","headerPrefix":"Bearer","autoRefresh":false,"clientAuthMethod":"basic"}'
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
  oauth2Config: '{"grantType":"implicit","authUrl":"","clientId":"","scope":"","callbackUrl":"","addTokenTo":"header","headerPrefix":"Bearer"}'
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
  oauth2Config: '{"grantType":"password","tokenUrl":"","clientId":"","clientSecret":"","scope":"","addTokenTo":"header","headerPrefix":"Bearer"}'
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
  oauth2Config: '{"grantType":"client_credentials","tokenUrl":"","clientId":"","clientSecret":"","scope":"","addTokenTo":"header","headerPrefix":"Bearer"}'
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
        row: [service, execute-api]                 # AWS signing name
      - attrs: { disabled: false }
        row: [session_token, "{{AWS_SESSION_TOKEN}}"]   # optional; temporary credentials only
```

The secure executor resolves these variables and signs the fully materialized request; the plugin runner only transports the descriptor and must not pre-sign or log credentials. Use `{{AWS_ACCESS_KEY_ID}}`, `{{AWS_SECRET_ACCESS_KEY}}`, and, for STS/role credentials, `{{AWS_SESSION_TOKEN}}`.

Supported `service` values are `s3` (Amazon S3), `execute-api` (API Gateway invocation), `apigateway` (API Gateway control plane), `lambda`, `dynamodb`, `iam`, `monitoring` (CloudWatch), `sns`, and `sqs`. Signing names are cryptographic protocol values: use `monitoring`, not `cloudwatch`, and `execute-api`, not `apigateway`, for API invocation.

Limitations: SigV4 requests expose redirects for manual handling, do not support `multipart/form-data`, and reject S3 paths containing dot-only (`.`, `..`, or `%2E`) segments. cURL export uses `--aws-sigv4`, `-u`, and an `X-Amz-Security-Token` header when needed, never a static signature. On import, the temporary-token header remains on the request; if the auth config has no `session_token`, the secure executor adopts that header, includes it in the signature, and redacts it from request metadata.

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
