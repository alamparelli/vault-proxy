# vault-proxy

Self-hosted secrets vault with HTTP proxy for authenticated API calls. Two binaries, zero runtime dependencies, single encrypted file for storage.

Credentials never leave the vault — the proxy injects them server-side. AI agents and tools call APIs through the proxy without ever seeing API keys.

## Features

- **AES-256-GCM encryption** at rest (key derived from master password via Argon2id)
- **HTTP proxy** with automatic credential injection (bearer, header, basic, OAuth2, service account)
- **OAuth2 token refresh** — lazy refresh at proxy time, tokens persist across restarts
- **Service account JWT exchange** — Google SA key files stored encrypted, RS256 JWT signed with stdlib
- **Encrypted file storage** — store credential files (SA JSONs, client secrets) in the vault
- **Scoped tokens** — `admin` for full CRUD, `proxy` for API calls only (safe to give to AI agents)
- **Zero runtime dependencies** — single static binary, no database, no external services

## Quick Start

### Build

```bash
git clone https://github.com/alamparelli/vault-proxy
cd vault-proxy
go build -o vault-server ./cmd/vault-server
go build -o vault-cli ./cmd/vault-cli
```

### Start the server

```bash
./vault-server --listen 127.0.0.1:8390 --data-dir ~/.vault-proxy
```

### Unlock (creates vault on first use)

```bash
./vault-cli unlock
# Enter master password when prompted
# Session token saved to ~/.vault-proxy/session
```

### Add a service

```bash
# Bearer token auth (most APIs)
./vault-cli service add '{
  "name": "openrouter",
  "base_url": "https://openrouter.ai/api",
  "auth": {"type": "bearer", "token": "sk-or-v1-xxxxx"}
}'

# Custom header auth
./vault-cli service add '{
  "name": "anthropic",
  "base_url": "https://api.anthropic.com",
  "auth": {"type": "header", "header_name": "x-api-key", "header_value": "sk-ant-xxxxx"}
}'

# OAuth2 with automatic token refresh
./vault-cli service add '{
  "name": "google-analytics",
  "base_url": "https://analyticsdata.googleapis.com",
  "auth": {
    "type": "oauth2_client",
    "client_id": "1234.apps.googleusercontent.com",
    "client_secret": "GOCSPX-xxx",
    "token_url": "https://oauth2.googleapis.com/token",
    "refresh_token": "1//0xxx",
    "scopes": ["https://www.googleapis.com/auth/analytics.readonly"]
  }
}'

# Google service account (upload SA key file first)
./vault-cli file upload my-sa-key service-account.json
./vault-cli service add '{
  "name": "bigquery",
  "base_url": "https://bigquery.googleapis.com",
  "auth": {
    "type": "service_account",
    "file_ref": "my-sa-key",
    "sa_scopes": ["https://www.googleapis.com/auth/bigquery.readonly"]
  }
}'
```

### Proxy a request

The vault injects credentials automatically. Your code never sees the secrets.

```bash
# Shorthand
./vault-cli proxy openrouter POST /v1/chat/completions \
  '{"model":"anthropic/claude-haiku-4-5","messages":[{"role":"user","content":"hello"}]}'

# Full syntax
./vault-cli http --service openrouter --method POST \
  --path /v1/chat/completions \
  --body '{"model":"anthropic/claude-haiku-4-5","messages":[...]}'
```

### Lock when done

```bash
./vault-cli lock
# Clears all secrets from memory, revokes all tokens
```

## Token Scopes

| Scope | Can do | Use case |
|-------|--------|----------|
| `admin` | Everything: CRUD services/files, create tokens, proxy | Human operator, setup |
| `proxy` | Proxy requests, list services (no secrets), health | AI agents, tools |

```bash
# Create a proxy-only token for an AI agent
./vault-cli token create proxy

# List active tokens
./vault-cli token list

# Revoke a token
./vault-cli token revoke a64f2e...
```

## File Storage

Store credential files (service account JSONs, client secrets) encrypted in the vault.

```bash
./vault-cli file upload google-secret client_secret_1009.json
./vault-cli file list
./vault-cli file download google-secret output.json
./vault-cli file delete google-secret
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_ADDR` | `http://127.0.0.1:8390` | Server address |
| `VAULT_TOKEN` | — | Session token (overrides `~/.vault-proxy/session`) |

## Server Flags

```
--listen    Address to listen on (default: 127.0.0.1:8390)
--data-dir  Directory for vault.enc (default: ~/.vault-proxy)
--token-ttl Token TTL (default: 24h)
```

## API Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | none | `{"status":"locked\|unlocked"}` |
| `POST` | `/auth/unlock` | none | Unlock vault, returns admin token |
| `POST` | `/auth/lock` | session | Lock vault, revoke all tokens |
| `GET` | `/services` | session | List services (no secrets) |
| `GET` | `/services/{name}` | session | Service info (no secrets) |
| `POST` | `/services` | admin | Add/update service |
| `DELETE` | `/services/{name}` | admin | Remove service |
| `ANY` | `/proxy/{service}/{path}` | session | Proxy with auth injection |
| `POST` | `/files` | admin | Upload file (multipart, 5MB max) |
| `GET` | `/files` | admin | List stored files |
| `GET` | `/files/{name}` | admin | Download file |
| `DELETE` | `/files/{name}` | admin | Delete file |
| `POST` | `/tokens` | admin | Create token |
| `GET` | `/tokens` | admin | List tokens |
| `DELETE` | `/tokens/{id}` | admin | Revoke token |

## Using from Go

```go
import "github.com/alamparelli/vault-proxy/pkg/client"

c := client.New() // reads VAULT_ADDR + VAULT_TOKEN from env
resp, err := c.Proxy("openrouter", "POST", "/v1/chat/completions", body)
```

## Using from any language

```bash
curl -X POST http://127.0.0.1:8390/proxy/openrouter/v1/chat/completions \
  -H "Authorization: Bearer $VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"...","messages":[...]}'
```

## Security

- Server binds to `127.0.0.1` only — never exposed externally
- All credentials encrypted at rest with AES-256-GCM (key from Argon2id)
- Proxy tokens can call APIs but never read or modify secrets
- Caller's `Authorization` header is stripped before forwarding
- SSRF protection: private/loopback/link-local IPs blocked, HTTPS enforced
- Brute-force protection on unlock with exponential backoff
- Every proxy call logged (service, method, path, status, duration — never credentials)
- `vault.enc.bak` backup created on every save
- Master password lost = no recovery

## License

[MIT](LICENSE)
