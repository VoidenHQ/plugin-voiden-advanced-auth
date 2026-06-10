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
- AWS Signature v4
- NTLM, Hawk, Atlassian ASAP, Netrc support
- Environment variable substitution in auth values
- Inherit authentication from parent collections
- Quick auth type switching via dropdown

## Usage

Use the `/auth` slash command to insert an authentication block, then select the auth type from the dropdown. Switch types at any time without losing configuration from other types.
