# Vault-Proxy Architecture

A lightweight, self-hosted secrets vault with an HTTP proxy for authenticated API calls.
Two binaries: a **vault server** (manages secrets, proxies requests) and a **CLI tool** (configures secrets, queries the vault).

## Threat Model

```
┌─────────────────────────────────────────────────────┐
│ Untrusted Zone (Claude / AI agent)                  │
│                                                     │
│  vault-cli http --service openrouter \              │
│    --method POST --path /chat/completions           │
│    --body '{"model":"..."}'                         │
│                                                     │
│  → Never sees credentials                           │
│  → Can only call pre-configured services            │
│  → All calls logged with caller context             │
└────────────────────┬────────────────────────────────┘
                     │ HTTP (localhost:VAULT_PORT)
                     │ Auth: session token (scoped, read-only)
┌────────────────────▼────────────────────────────────┐
│ Vault Server                                        │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ Auth     │  │ Secrets  │  │ HTTP Proxy       │  │
│  │ (master  │  │ Store    │  │ (inject auth,    │  │
│  │  passwd) │  │ (AES-256)│  │  forward request)│  │
│  └──────────┘  └──────────┘  └──────────────────┘  │
│                                                     │
│  Storage: vault.enc (AES-256-GCM, key derived      │
│  from master password via Argon2id)                 │
└─────────────────────────────────────────────────────┘
```

## Components

### 1. Vault Server (`cmd/vault-server/`)

Long-running process. Listens on localhost (never exposed externally).

**Startup flow:**
1. Read `vault.enc` from `--data-dir`
2. If first run → prompt for master password, create vault
3. Derive encryption key from master password (Argon2id)
4. Decrypt vault into memory
5. Start HTTP API on `--listen` (default: `127.0.0.1:8390`)

**API endpoints:**

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/auth/unlock` | master password | Returns session token |
| `POST` | `/auth/lock` | session | Locks vault, clears memory |
| `GET` | `/services` | session | List configured services (no secrets) |
| `GET` | `/services/{name}` | session | Service config (no secrets) |
| `POST` | `/services` | session (admin) | Add/update a service |
| `DELETE` | `/services/{name}` | session (admin) | Remove a service |
| `POST` | `/proxy/{service}/{path...}` | session | Proxy HTTP request with injected auth |
| `GET` | `/proxy/{service}/{path...}` | session | Same, for GET requests |
| `PUT` | `/proxy/{service}/{path...}` | session | Same, for PUT requests |
| `DELETE`| `/proxy/{service}/{path...}` | session | Same, for DELETE requests |
| `GET` | `/health` | none | Liveness check |
| `POST` | `/files` | session (admin) | Upload a credential file |
| `GET` | `/files/{name}` | session (admin) | Download a credential file |
| `DELETE`| `/files/{name}` | session (admin) | Delete a credential file |

**Session tokens:**
- Two scopes: `admin` (full CRUD) and `proxy` (read-only, proxy only)
- `proxy` tokens are what CLI tools use — can call APIs but not read/modify secrets
- Tokens are short-lived (configurable TTL, default 24h)
- Stored in memory only (no persistence)

### 2. CLI Tool (`cmd/vault-cli/`)

Stateless binary. Talks to the vault server via HTTP.

```
vault-cli unlock                          # authenticate, get session token
vault-cli lock                            # lock the vault

vault-cli service list                    # list configured services
vault-cli service add <name>              # interactive: type, base_url, credentials
vault-cli service remove <name>           # delete a service
vault-cli service test <name>             # make a test request to verify credentials

vault-cli http --service <name> \         # proxy an HTTP request
  --method POST \
  --path /v1/chat/completions \
  --header "Content-Type: application/json" \
  --body '{"model":"..."}'

vault-cli file upload <name> <path>       # upload credential file (e.g. service account JSON)
vault-cli file list                       # list stored files
vault-cli file delete <name>              # delete stored file

vault-cli token create --scope proxy      # create a proxy-only token (for AI agents)
vault-cli token list                      # list active tokens
vault-cli token revoke <id>               # revoke a token
```

**Session management:**
- `unlock` saves session token to `~/.vault-proxy/session` (mode 0600)
- All subsequent commands use this token
- `lock` deletes the session file and locks server-side

### 3. Crypto Layer (`internal/crypto/`)

- Master password → Argon2id → 256-bit key
- Vault file: `[salt:16][nonce:12][ciphertext][tag:16]`
- AES-256-GCM for encryption
- Salt stored in cleartext header, unique per save
- Key never written to disk, only in server memory while unlocked

### 4. Secrets Store (`internal/vault/`)

In-memory vault, serialized to encrypted JSON on mutations.

```go
type Vault struct {
    Services map[string]Service `json:"services"`
    Files    map[string]File    `json:"files"`
}

type Service struct {
    Name    string `json:"name"`
    BaseURL string `json:"base_url"`
    Auth    Auth   `json:"auth"`
}

type Auth struct {
    Type         string `json:"type"`          // bearer, header, basic, oauth2_client, service_account
    // bearer
    Token        string `json:"token,omitempty"`
    // header
    HeaderName   string `json:"header_name,omitempty"`
    HeaderValue  string `json:"header_value,omitempty"`
    // basic
    Username     string `json:"username,omitempty"`
    Password     string `json:"password,omitempty"`
    // oauth2_client (phase 2)
    ClientID     string `json:"client_id,omitempty"`
    ClientSecret string `json:"client_secret,omitempty"`
    RefreshToken string `json:"refresh_token,omitempty"`
    TokenURL     string `json:"token_url,omitempty"`
    AccessToken  string `json:"access_token,omitempty"`
    ExpiresAt    string `json:"expires_at,omitempty"`
    Scopes       []string `json:"scopes,omitempty"`
    // service_account (phase 2)
    FileRef      string `json:"file_ref,omitempty"` // reference to Files entry
}

type File struct {
    Name     string `json:"name"`
    MimeType string `json:"mime_type"`
    Data     []byte `json:"data"` // stored encrypted in vault
}
```

### 5. HTTP Proxy (`internal/api/`)

The proxy handler:
1. Receives request: `POST /proxy/openrouter/v1/chat/completions`
2. Looks up `openrouter` in vault
3. Builds outbound request: `POST https://openrouter.ai/api/v1/chat/completions`
4. Injects auth based on type:
   - `bearer` → `Authorization: Bearer <token>`
   - `header` → `<header_name>: <header_value>`
   - `basic` → `Authorization: Basic <base64(user:pass)>`
   - `oauth2_client` → auto-refresh if expired, then bearer
   - `service_account` → JWT exchange, then bearer
5. Forwards request body and caller headers (minus auth)
6. Returns response to caller
7. Logs: service, method, path, status, duration (never credentials)

## Phases

### Phase 1 — Core Vault + Bearer Auth
- [ ] Crypto layer (Argon2id + AES-256-GCM)
- [ ] Vault store (in-memory + encrypted file persistence)
- [ ] Server: `/auth/unlock`, `/auth/lock`, `/health`
- [ ] Server: `/services` CRUD
- [ ] Server: `/proxy` with bearer and header auth injection
- [ ] CLI: `unlock`, `lock`, `service add/list/remove`, `http`
- [ ] CLI: `token create/list/revoke`
- [ ] Audit logging (every proxy call logged)
- [ ] Basic auth type support
- [ ] Tests for crypto, vault, proxy

### Phase 2 — OAuth2 + Service Accounts
- [ ] OAuth2 client credentials flow (auto token refresh)
- [ ] Service account file storage + JWT signing
- [ ] File upload/download endpoints
- [ ] CLI: `file upload/list/delete`, `service test`
- [ ] Token rotation and expiry management

### Phase 3 — OAuth2 Consent Flow
- [ ] OAuth2 authorization code flow (redirect-based)
- [ ] Callback handler in server
- [ ] CLI: `service connect <name>` (opens browser for consent)
- [ ] PKCE support

### Phase 4 — Distribution
- [ ] `curl -fsSL install.vault-proxy.dev | sh` installer
- [ ] Docker image
- [ ] ALF integration (tools.d/ symlink)
- [ ] Homebrew formula

## Integration with ALF

```
# In ALF's Docker container:
vault-cli http --service openrouter --method POST \
  --path /v1/chat/completions \
  --body '{"model":"claude-haiku-4-5","messages":[...]}'
```

- Vault server runs as sidecar container or on host
- ALF daemon creates a `proxy`-scoped token at startup
- Token passed to Claude via env var `VAULT_TOKEN`
- Claude uses `vault-cli http` (in tools.d/) — can proxy requests but never see secrets
- Admin operations (add/remove services) require `admin` token (CC UI or host CLI only)

## Security Hardening

Findings from ALF's automated security audit (2026-03-05) that Vault-Proxy resolves or mitigates.

### Solved by design

| Risk | Before (tools manage their own secrets) | With Vault-Proxy |
|------|----------------------------------------|------------------|
| **Plaintext token files** (OAuth tokens as 0644 JSON) | Tools write `token.json` to disk, readable by any process | All credentials in `vault.enc` (AES-256-GCM). No plaintext on disk. |
| **Hardcoded client IDs** (GCP project IDs in source code) | `client_secret_1009...apps.googleusercontent.com.json` in tool source | Client secret files stored in vault's encrypted `Files` store. Source code references service names, never credentials. |
| **Tokens in process memory** (`SECRET = open(file).read()`) | Each tool loads and holds credentials for its entire lifetime | Tools never see credentials. Vault server holds them in one isolated process with a controlled lifecycle (`lock` clears memory). |
| **No file permission validation** (tokens at 0644) | Tools don't check permissions; any container process can read tokens | No token files to protect. Vault session file enforced at 0600. |

### Proxy-level protections

These protections apply to all proxied requests regardless of how the calling tool is written.

**Request validation:**
- Outbound URLs restricted to the service's configured `base_url` — prevents SSRF via path manipulation
- Request body size limit per service (configurable, default 10MB) — prevents OOM from unbounded payloads
- Response body size limit per service (configurable, default 50MB) — prevents OOM from malicious API responses
- Timeout per service (configurable, default 30s) — prevents hung connections

**URL and host validation:**
- `base_url` must be HTTPS (reject HTTP unless explicitly allowed for localhost)
- Path traversal in proxy path (`/proxy/svc/../../../etc/passwd`) rejected by URL normalization
- No support for `javascript:`, `data:`, or other non-HTTP schemes

**Auth injection safety:**
- Auth headers are injected server-side, never exposed in proxy response headers
- Caller-provided `Authorization` headers are stripped before forwarding (prevents override)
- OAuth2 token refresh happens server-side; refresh tokens never leave the vault

**Audit logging:**
- Every proxy call logged: `timestamp, service, method, path, status, duration, caller_token_id`
- Credentials never logged — not in request, not in response, not in errors
- Token creation/revocation logged with admin context
- Log rotation configurable (default: daily, 30 days retention)

### Network isolation

```
┌─────────────────────────────────┐
│ Host / Sidecar                  │
│                                 │
│   vault-server                  │
│   127.0.0.1:8390  ◄─────────── │ ──── Never exposed externally
│                                 │
└───────────┬─────────────────────┘
            │ Docker network or localhost
┌───────────▼─────────────────────┐
│ ALF Container                   │
│                                 │
│   Claude / tools                │
│   → vault-cli http (proxy-only) │
│   → VAULT_TOKEN env var         │
│   → Cannot reach vault admin API│
└─────────────────────────────────┘
```

- Server binds to `127.0.0.1` only (or Docker internal network)
- No external port exposure — tools inside the container reach vault via internal network
- `proxy` tokens cannot access `/services` CRUD or `/files` — only `/proxy/*` and `/health`
- Even if a `proxy` token leaks, attacker can only call pre-configured services, not read credentials

### Edge cases to handle

- **Vault locked while tools are running**: proxy returns 503 with `Retry-After` header. Tools should handle gracefully.
- **Token expiry mid-request**: if a proxy token expires during a long request, the request completes but subsequent requests fail with 401. Tools retry with a fresh token from `VAULT_TOKEN`.
- **Concurrent OAuth2 refresh**: mutex on per-service token refresh to prevent thundering herd against the OAuth2 provider.
- **Vault file corruption**: keep one backup (`vault.enc.bak`) on each successful save. CLI `vault-cli backup` exports encrypted copy.
- **Master password lost**: no recovery. Document this clearly. Encourage users to store master password in a password manager.

## Tech Stack

- **Language**: Go (single static binary, matches ALF)
- **Crypto**: `golang.org/x/crypto` (argon2, aes-gcm from stdlib)
- **HTTP**: `net/http` stdlib (chi router optional)
- **Storage**: Single encrypted file (no external dependencies)
- **Zero dependencies** at runtime — single binary, no database, no external services
