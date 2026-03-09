# Vault-Proxy — Standalone Installation

Self-hosted secrets vault with HTTP proxy for authenticated API calls.
Two binaries, zero runtime dependencies, single encrypted file for storage.

## Quick Start

### 1. Build

```bash
git clone https://github.com/alessandrolamparelli/vault-proxy
cd vault-proxy
go build -o vault-server ./cmd/vault-server
go build -o vault-cli ./cmd/vault-cli
```

### 2. Start the server

```bash
./vault-server --listen 127.0.0.1:8390 --data-dir ~/.vault-proxy
```

On first run, there's no vault file — it will be created when you unlock.

### 3. Unlock (creates vault on first use)

```bash
./vault-cli unlock
# Enter master password when prompted
# Session token saved to ~/.vault-proxy/session
```

### 4. Add a service

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

# Basic auth
./vault-cli service add '{
  "name": "internal-api",
  "base_url": "https://api.internal.com",
  "auth": {"type": "basic", "username": "admin", "password": "secret"}
}'
```

### 5. Proxy a request

The vault injects credentials automatically. Your code never sees the secrets.

```bash
# Full syntax
./vault-cli http --service openrouter --method POST \
  --path /v1/chat/completions \
  --body '{"model":"anthropic/claude-haiku-4-5","messages":[{"role":"user","content":"hello"}]}'

# Shorthand (same thing)
./vault-cli proxy openrouter POST /v1/chat/completions \
  '{"model":"anthropic/claude-haiku-4-5","messages":[{"role":"user","content":"hello"}]}'
```

### 6. Lock when done

```bash
./vault-cli lock
# Clears all secrets from memory, revokes all tokens
```

## Token Scopes

Two scopes control access:

| Scope | Can do | Use case |
|-------|--------|----------|
| `admin` | Everything: CRUD services, create tokens, proxy | Human operator, setup |
| `proxy` | Proxy requests, list services (no secrets), health | AI agents, tools |

```bash
# Create a proxy-only token for an AI agent
./vault-cli token create proxy
# Output: a64f2e...  (give this to the agent)

# List active tokens
./vault-cli token list

# Revoke a token
./vault-cli token revoke a64f2e...
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

## Using from Go code

Any Go tool can import the client directly:

```go
import "github.com/alessandrolamparelli/vault-proxy/internal/client"

c := client.New() // reads VAULT_ADDR + VAULT_TOKEN from env
resp, err := c.Proxy("openrouter", "POST", "/v1/chat/completions", body)
```

## Using from any language

The vault exposes a standard HTTP API. Any language can call it:

```bash
# Direct HTTP (same as what vault-cli does)
curl -X POST http://127.0.0.1:8390/proxy/openrouter/v1/chat/completions \
  -H "Authorization: Bearer $VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"...","messages":[...]}'
```

## Security Notes

- Server binds to `127.0.0.1` only — never exposed externally
- All credentials encrypted at rest with AES-256-GCM (key from Argon2id)
- Proxy tokens can call APIs but never read or modify secrets
- Caller's `Authorization` header is stripped before forwarding
- Every proxy call logged (service, method, path, status, duration — never credentials)
- `vault.enc.bak` backup created on every save
- Master password lost = no recovery. Store it in a password manager.

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
| `POST` | `/tokens` | admin | Create token |
| `GET` | `/tokens` | admin | List tokens |
| `DELETE` | `/tokens/{id}` | admin | Revoke token |
