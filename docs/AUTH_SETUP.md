# Authentication Setup Guide

This document covers how to configure each authentication method in vault-proxy. All examples assume the vault server runs at `http://localhost:8400` and you have an admin token.

Base URL: `http://localhost:8400`
Admin header: `Authorization: Bearer ADMIN_TOKEN`

---

## File Management

Some auth types reference files stored in the vault. Upload files before creating services that need them.

### Upload a file

```bash
curl -X POST http://localhost:8400/files \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -F "name=my-credentials.json" \
  -F "file=@/path/to/my-credentials.json"
```

### List files

```bash
curl http://localhost:8400/files \
  -H "Authorization: Bearer ADMIN_TOKEN"
```

### Delete a file

```bash
curl -X DELETE http://localhost:8400/files/my-credentials.json \
  -H "Authorization: Bearer ADMIN_TOKEN"
```

---

## Auth Type: `bearer`

Simple static bearer token. Use when the API gives you a long-lived API key or token.

### Required fields

| Field | Description |
|-------|-------------|
| `token` | The bearer token value |

### Example

```bash
curl -X POST http://localhost:8400/services \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "openai",
    "base_url": "https://api.openai.com",
    "auth": {
      "type": "bearer",
      "token": "sk-..."
    }
  }'
```

### Behavior

Every proxied request gets an `Authorization: Bearer <token>` header injected. No refresh logic.

---

## Auth Type: `header`

Custom header injection. Use when an API expects a non-standard auth header (e.g., `X-API-Key`).

### Required fields

| Field | Description |
|-------|-------------|
| `header_name` | Header name to set |
| `header_value` | Header value |

### Restricted headers

The following headers cannot be used: `host`, `transfer-encoding`, `content-length`, `connection`, `upgrade`, `te`, `trailer`.

### Example

```bash
curl -X POST http://localhost:8400/services \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "stripe",
    "base_url": "https://api.stripe.com",
    "auth": {
      "type": "header",
      "header_name": "X-API-Key",
      "header_value": "sk_live_..."
    }
  }'
```

### Behavior

Every proxied request gets the custom header injected. No refresh logic.

---

## Auth Type: `basic`

HTTP Basic authentication. Use for APIs that require username/password auth.

### Required fields

| Field | Description |
|-------|-------------|
| `username` | Username |
| `password` | Password |

### Example

```bash
curl -X POST http://localhost:8400/services \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "jira",
    "base_url": "https://mycompany.atlassian.net",
    "auth": {
      "type": "basic",
      "username": "user@example.com",
      "password": "api-token-here"
    }
  }'
```

### Behavior

Every proxied request gets an `Authorization: Basic <base64(user:pass)>` header. No refresh logic.

---

## Auth Type: `oauth2_client`

OAuth2 with automatic token refresh. Three setup modes: browser-based (easiest), file-based, or manual.

### Option A: Browser authorization (easiest for Google)

Upload only the `client_secret_*.json` file. The vault handles the entire OAuth2 consent flow — opens a browser, receives the callback, gets the refresh token, and creates the service automatically.

**Step 1: Upload client secret file**

```bash
curl -X POST http://localhost:8400/files \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -F "name=google-client-secret.json" \
  -F "file=@/path/to/client_secret_1234.apps.googleusercontent.com.json"
```

**Step 2: Start the authorization flow**

```bash
curl -X POST http://localhost:8400/auth/oauth2/authorize \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_secret_file": "google-client-secret.json",
    "service_name": "google-gmail",
    "base_url": "https://gmail.googleapis.com",
    "scopes": ["https://www.googleapis.com/auth/gmail.readonly"]
  }'
```

Response:
```json
{
  "auth_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
  "state": "abc123...",
  "redirect_uri": "http://localhost:...",
  "message": "Open auth_url in your browser to authorize."
}
```

**Step 3: Open `auth_url` in your browser**

Authorize the app. Google redirects back to the vault's callback endpoint. The vault exchanges the code for tokens and creates the service automatically. You see a success page in the browser.

No `token.json` needed. The vault gets the refresh token directly from Google.

The authorization link expires after 5 minutes. The `redirect_uri` in the client_secret file must point to localhost (standard for desktop OAuth2 apps).

### Option B: File-based setup

Upload both `client_secret_*.json` and `token.json` files. Use this if you already have a `token.json` from a previous OAuth2 flow.

**Step 1: Upload files**

```bash
curl -X POST http://localhost:8400/files \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -F "name=google-client-secret.json" \
  -F "file=@/path/to/client_secret_1234.apps.googleusercontent.com.json"

curl -X POST http://localhost:8400/files \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -F "name=google-token.json" \
  -F "file=@/path/to/token.json"
```

**Step 2: Create service**

```bash
curl -X POST http://localhost:8400/services \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "google-gmail",
    "base_url": "https://gmail.googleapis.com",
    "auth": {
      "type": "oauth2_client",
      "client_secret_file": "google-client-secret.json",
      "token_file": "google-token.json",
      "scopes": ["https://www.googleapis.com/auth/gmail.readonly"]
    }
  }'
```

The vault reads both files, extracts `client_id`, `client_secret`, `refresh_token`, and `token_url`, then stores them as standard `oauth2_client` fields.

**Expected file formats:**

`client_secret_*.json` (top-level key can be `"installed"` or `"web"`):
```json
{
  "installed": {
    "client_id": "1234.apps.googleusercontent.com",
    "client_secret": "GOCSPX-...",
    "token_uri": "https://oauth2.googleapis.com/token"
  }
}
```

`token.json` (only `refresh_token` is used):
```json
{
  "refresh_token": "1//0e..."
}
```

### Option C: Manual fields

Provide credentials directly. Works with any OAuth2 provider (Google, GitHub, etc).

```bash
curl -X POST http://localhost:8400/services \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "google-drive",
    "base_url": "https://www.googleapis.com",
    "auth": {
      "type": "oauth2_client",
      "client_id": "1234.apps.googleusercontent.com",
      "client_secret": "GOCSPX-...",
      "refresh_token": "1//0e...",
      "token_url": "https://oauth2.googleapis.com/token",
      "scopes": ["https://www.googleapis.com/auth/drive.readonly"]
    }
  }'
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `client_id` | Yes* | OAuth2 client ID |
| `client_secret` | Yes* | OAuth2 client secret |
| `refresh_token` | Yes* | OAuth2 refresh token |
| `token_url` | Yes* | Token endpoint URL (must be HTTPS) |
| `client_secret_file` | Alt* | Name of uploaded Google client secret file |
| `token_file` | Alt* | Name of uploaded Google token file |
| `scopes` | No | OAuth2 scopes to request on refresh |

*Provide either (`client_id` + `client_secret` + `refresh_token` + `token_url`), or (`client_secret_file` + `token_file`), or use the browser flow via `/auth/oauth2/authorize`.

### Behavior

On every proxied request:
1. If the cached access token is still valid (> 30s until expiry), it is used directly
2. If expired or missing, the vault exchanges the refresh token for a new access token
3. The new token is persisted to the vault
4. `Authorization: Bearer <access_token>` is injected into the request

If the provider rotates the refresh token (some do), the new refresh token is also persisted.

---

## Auth Type: `service_account`

Google service account JWT exchange. Use when you have a Google service account key file (with a private key). No user consent needed.

### Prerequisites

Download the service account key JSON from Google Cloud Console > IAM > Service Accounts > Keys.

### Step 1: Upload the service account key file

```bash
curl -X POST http://localhost:8400/files \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -F "name=my-sa-key.json" \
  -F "file=@/path/to/service-account-key.json"
```

### Step 2: Create the service

```bash
curl -X POST http://localhost:8400/services \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "gcp-storage",
    "base_url": "https://storage.googleapis.com",
    "auth": {
      "type": "service_account",
      "file_ref": "my-sa-key.json",
      "sa_scopes": ["https://www.googleapis.com/auth/devstorage.read_only"]
    }
  }'
```

### Required fields

| Field | Description |
|-------|-------------|
| `file_ref` | Name of the uploaded service account key file (must exist in vault files) |

### Optional fields

| Field | Description |
|-------|-------------|
| `sa_scopes` | OAuth2 scopes to request |
| `sa_token_url` | Token endpoint URL (defaults to `https://oauth2.googleapis.com/token`) |

### Behavior

On every proxied request:
1. If the cached SA token is still valid (> 30s until expiry), it is used directly
2. If expired or missing, the vault builds a signed JWT from the service account key and exchanges it for an access token
3. The access token is persisted to the vault
4. `Authorization: Bearer <access_token>` is injected into the request

### Expected file format

```json
{
  "client_email": "my-sa@project.iam.gserviceaccount.com",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n",
  "token_uri": "https://oauth2.googleapis.com/token"
}
```

---

## Using the Proxy

Once a service is configured, make requests through the proxy. The vault injects auth automatically.

```bash
# Proxy a GET request to the "google-gmail" service
curl http://localhost:8400/proxy/google-gmail/gmail/v1/users/me/messages \
  -H "Authorization: Bearer PROXY_TOKEN"

# Proxy a POST request
curl -X POST http://localhost:8400/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer PROXY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]}'
```

The proxy token is a vault session token (obtained from `/auth/unlock`), not the upstream API token. The vault replaces it with the service's credentials.

### URL mapping

`/proxy/{service_name}/{path}` maps to `{service.base_url}/{path}`

Query parameters are forwarded as-is.

---

## Optional: TLS Skip Verify

For internal services with self-signed certificates, add `tls_skip_verify: true`. This relaxes HTTPS requirements and SSRF IP checks (except cloud metadata IPs which are always blocked).

```json
{
  "name": "internal-api",
  "base_url": "https://10.0.1.5:8443",
  "tls_skip_verify": true,
  "auth": {
    "type": "bearer",
    "token": "internal-token"
  }
}
```

---

## Token Scopes

The vault uses two token scopes:

| Scope | Can do |
|-------|--------|
| `admin` | Everything: manage services, files, tokens, and proxy requests |
| `proxy` | List services, proxy requests only |

Create a proxy-scoped token for clients that only need to make API calls:

```bash
curl -X POST http://localhost:8400/tokens \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scope": "proxy"}'
```
