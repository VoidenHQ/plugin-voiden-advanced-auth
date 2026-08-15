> A plugin for [Voiden](https://github.com/VoidenHQ) — the developer-first API client.

# Advanced Authentication

Full authentication support for HTTP and REST APIs — Bearer, Basic, API Key, OAuth 1.0/2.0, Digest, AWS Signature v4, and more.

## Features

- Bearer Token authentication
- Basic authentication (username / password)
- API Key authentication (header or query parameter)
- OAuth 2.0 with customizable token types
- OAuth 1.0 with signature generation
- Digest authentication
- AWS Signature v4 for S3, API Gateway, Lambda, DynamoDB, IAM, CloudWatch, SNS, and SQS
- NTLM, Hawk, Atlassian ASAP, Netrc support
- Environment variable substitution in auth values
- Inherit authentication from parent collections
- Quick auth type switching via dropdown

## Usage

Use the `/auth` slash command to insert an authentication block, then select the auth type from the dropdown. Switch types at any time without losing configuration from other types.

## AWS Signature v4

AWS signing is performed by Voiden's secure executor after variables, URL parameters, headers, and body are resolved. The plugin only passes an auth descriptor; it does not resolve, sign, or log credentials.

| Field | Description |
|---|---|
| `access_key` | Access key ID, usually `{{AWS_ACCESS_KEY_ID}}` |
| `secret_key` | Secret access key, usually `{{AWS_SECRET_ACCESS_KEY}}` |
| `session_token` | Optional token for temporary STS/role credentials, usually `{{AWS_SESSION_TOKEN}}` |
| `region` | AWS region, for example `us-east-1` |
| `service` | AWS signing service from the list below |

Supported signing services: S3 (`s3`), API Gateway invocation (`execute-api`), API Gateway control plane (`apigateway`), Lambda (`lambda`), DynamoDB (`dynamodb`), IAM (`iam`), CloudWatch (`monitoring`), SNS (`sns`), and SQS (`sqs`). In particular, CloudWatch does **not** use `cloudwatch` as its cryptographic signing name, and API Gateway invocation does **not** use `apigateway`.

Use `{{VARIABLE_NAME}}` values rather than storing credentials in `.void` files. Temporary credentials require all three values: access key, secret key, and session token.

### Limitations

- Redirects are returned to the caller and must be followed manually because a changed URL requires a new signature.
- `multipart/form-data` is not supported for signed requests because deterministic body bytes are unavailable in this pipeline.
- S3 object paths containing dot-only segments (`.`, `..`, or equivalent `%2E` forms) are rejected because Fetch normalizes them after signing.
- Copy as cURL uses curl's `--aws-sigv4` plus `-u`, and adds `X-Amz-Security-Token` for temporary credentials; it never exports a static signature. On import, that header remains on the request, and when `session_token` is absent from the auth config the secure executor adopts the imported header and includes it in the signature.
