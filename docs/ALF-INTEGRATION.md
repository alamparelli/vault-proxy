# Vault-Proxy — ALF Integration

How to integrate vault-proxy with [ALF](https://github.com/alessandrolamparelli/alf) so Claude can call APIs without seeing credentials.

## Architecture

```
apt┌─────────────────────────────────────────────────┐
│ Host                                            │
│                                                 │
│  vault-server (127.0.0.1:8390)                  │
│  ├── vault.enc (encrypted secrets)              │
│  └── admin token → passed to ALF daemon         │
│                                                 │
└───────────┬─────────────────────────────────────┘
            │ Docker network / localhost
┌───────────▼─────────────────────────────────────┐
│ ALF Container                                   │
│                                                 │
│  alf-daemon (uid=1000)                          │
│  ├── VAULT_ADMIN_TOKEN (from secret)            │
│  ├── Creates proxy token for Claude at startup  │
│  └── Control Center :8080                       │
│       └── /vault page (admin UI for secrets)    │
│           ├── List / add / remove services      │
│           ├── Test service connectivity          │
│           └── Manage tokens                     │
│                                                 │
│  Claude subprocess (uid=1001)                   │
│  ├── VAULT_TOKEN=<proxy-scope>                  │
│  ├── VAULT_ADDR=http://host:8390                │
│  └── vault (in tools.d/, on PATH)               │
│       → vault proxy <svc> <method> <path> [body]│
│       → Never sees API keys                     │
│       → All calls logged                        │
└─────────────────────────────────────────────────┘
```

## Setup

### 1. Build vault-cli for the container

```bash
# From vault-proxy repo — static build for Linux (container target)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o vault-cli ./cmd/vault-cli
```

### 2. Add to ALF Dockerfile

```dockerfile
# Copy vault-cli binary
COPY --from=vault-builder /vault-cli /opt/alf/bin/vault-cli

# Symlink as "vault" in tools.d/ (multi-call pattern)
RUN ln -s /opt/alf/bin/vault-cli /opt/alf/tools.d/vault
```

The symlink name matters: when invoked as `vault`, the binary uses the shorthand syntax that's easy for Claude to use.

### 3. Configure docker-compose.yml

```yaml
services:
  alf:
    # ...existing config...
    environment:
      - VAULT_ADDR=http://host.docker.internal:8390
      - VAULT_ADMIN_TOKEN_FILE=/run/secrets/vault_admin_token
    extra_hosts:
      - "host.docker.internal:host-gateway"  # Linux only
    secrets:
      - vault_admin_token

secrets:
  vault_admin_token:
    file: ./secrets/vault_admin_token
```

### 4. Pass VAULT_TOKEN to Claude subprocess

In ALF's provider, add `VAULT_TOKEN` to the safe env allowlist:

```go
// internal/provider/cli.go — safeEnv()
// Add to the allowlist:
"VAULT_TOKEN",
"VAULT_ADDR",
```

Or pass via `params.Env`:

```go
params.Env = append(params.Env,
    "VAULT_TOKEN="+os.Getenv("VAULT_TOKEN"),
    "VAULT_ADDR="+os.Getenv("VAULT_ADDR"),
)
```

### 5. Bootstrap on daemon startup

In `cmd/alf-daemon/main.go`, after vault-server is reachable:

```go
// Create a proxy-scoped token for Claude
// (requires admin token — stored as daemon secret)
vaultClient := client.NewWithToken(
    os.Getenv("VAULT_ADDR"),
    os.Getenv("VAULT_ADMIN_TOKEN"),
)
proxyToken, err := vaultClient.CreateToken("proxy")
if err != nil {
    log.Printf("vault-proxy not available: %v", err)
} else {
    os.Setenv("VAULT_TOKEN", proxyToken)
}
```

## Control Center — Vault Page

The CC acts as the admin UI for vault-proxy. The daemon holds an `admin` token, so the CC can do full CRUD without exposing vault-cli to the user.

### CC Backend: vault handlers

Add to `internal/controlcenter/handler_vault.go`:

```go
// All handlers proxy to vault-server using the daemon's admin token.
// The CC auth (magic link) protects access — only the authorized user
// can manage secrets.

// GET  /api/vault/status     → vault health + unlock state
// POST /api/vault/unlock     → unlock vault (CC prompts for master password)
// POST /api/vault/lock       → lock vault

// GET  /api/vault/services   → list services (safe info only)
// POST /api/vault/services   → add/update service
// DELETE /api/vault/services/{name} → remove service
// POST /api/vault/services/{name}/test → test connectivity

// GET  /api/vault/tokens     → list active tokens (masked IDs)
// POST /api/vault/tokens     → create token
// DELETE /api/vault/tokens/{id} → revoke token
```

Implementation pattern — thin proxy to vault-server:

```go
type VaultHandler struct {
    vaultClient *client.Client // admin-scoped
}

func (h *VaultHandler) ListServices(w http.ResponseWriter, r *http.Request) {
    services, err := h.vaultClient.ListServices()
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadGateway)
        return
    }
    json.NewEncoder(w).Encode(services)
}

func (h *VaultHandler) AddService(w http.ResponseWriter, r *http.Request) {
    // Read JSON from CC frontend, forward to vault-server
    resp, err := h.doRaw("POST", "/services", r.Body)
    // ...forward response
}

func (h *VaultHandler) TestService(w http.ResponseWriter, r *http.Request) {
    name := chi.URLParam(r, "name")
    // Make a lightweight GET request through the proxy to verify credentials work
    resp, err := h.vaultClient.Proxy(name, "GET", "/", nil)
    // Return status code + latency to frontend
}
```

### CC Frontend: vault page

The page fits the existing CC UI pattern (like tools/skills pages):

```
┌─────────────────────────────────────────────┐
│ Vault                              [Lock 🔒]│
├─────────────────────────────────────────────┤
│                                             │
│ Services                          [+ Add]   │
│ ┌─────────────────────────────────────────┐ │
│ │ openrouter    https://openrouter.ai/api │ │
│ │ bearer        ✅ connected     [Delete] │ │
│ ├─────────────────────────────────────────┤ │
│ │ anthropic     https://api.anthropic.com │ │
│ │ header        ✅ connected     [Delete] │ │
│ ├─────────────────────────────────────────┤ │
│ │ github        https://api.github.com    │ │
│ │ bearer        ❌ 401           [Delete] │ │
│ └─────────────────────────────────────────┘ │
│                                             │
│ Active Tokens                               │
│ ┌─────────────────────────────────────────┐ │
│ │ a64f2e... proxy  expires in 23h [Revoke]│ │
│ │ 938def... admin  expires in 22h [Revoke]│ │
│ └─────────────────────────────────────────┘ │
│                                             │
│ [+ Create Token]                            │
└─────────────────────────────────────────────┘
```

**Add Service modal:**
```
┌─────────────────────────────────────┐
│ Add Service                         │
│                                     │
│ Name:     [openrouter            ]  │
│ Base URL: [https://openrouter.ai/api]│
│                                     │
│ Auth Type: [bearer ▾]               │
│ Token:    [sk-or-v1-xxxxx       ]   │
│                                     │
│           [Cancel]  [Add & Test]    │
└─────────────────────────────────────┘
```

Auth type dropdown shows fields conditionally:
- `bearer` → Token
- `header` → Header Name + Header Value
- `basic` → Username + Password

### Unlock flow

If the vault is locked when the CC page loads:

1. CC shows "Vault is locked" with a password input
2. User enters master password in the CC UI
3. CC posts to `/api/vault/unlock` → daemon forwards to vault-server
4. On success, CC gets admin token, stores it in daemon memory
5. Page reloads with full service/token management

This replaces the need to SSH into the host and run `vault-cli unlock`.

## How Claude Uses It

Once integrated, Claude sees `vault` in the auto-generated `toolbox.md` and can call:

```bash
# Claude calls this (simple, positional args):
vault proxy openrouter POST /v1/chat/completions '{"model":"claude-haiku-4-5","messages":[...]}'

# Or for GET requests:
vault proxy github GET /repos/user/repo/issues

# List available services:
vault-cli service list
```

Claude **never** sees or handles API keys. The vault injects them server-side.

## Optional: Skill for context

Create `skills.d/vault/SKILL.md` to give Claude context about available services:

```yaml
---
name: vault-api
description: Instructions for using vault-proxy to call external APIs
version: "1"
triggers: [api, openrouter, anthropic, github]
tier: haiku
---

# API Access via Vault

You have access to external APIs through the `vault` tool.
Never try to use API keys directly — always go through the vault proxy.

## Available commands

```bash
# Proxy a request (auth injected automatically)
vault proxy <service> <METHOD> <path> [body]

# List available services
vault-cli service list
```

## Example

```bash
vault proxy openrouter POST /v1/chat/completions '{
  "model": "anthropic/claude-haiku-4-5",
  "messages": [{"role": "user", "content": "hello"}]
}'
```
```

## Sidecar vs Host deployment

### Option A: Vault on host (recommended)

- Vault-server runs on the host machine
- Container reaches it via `host.docker.internal`
- Master password managed via CC unlock page or host CLI
- Simplest setup, survives container restarts

### Option B: Vault as sidecar container

```yaml
services:
  vault:
    image: vault-proxy:latest
    command: vault-server --listen 0.0.0.0:8390 --data-dir /data
    volumes:
      - vault-data:/data
    networks:
      - alf-internal

  alf:
    environment:
      - VAULT_ADDR=http://vault:8390
    networks:
      - alf-internal

networks:
  alf-internal:
    internal: true  # No external access
```

With sidecar, unlock the vault via the CC page on first boot.

## Security Considerations

- CC auth (magic link) gates all vault admin operations — only the authorized user can manage secrets
- `proxy` tokens **cannot** read or modify secrets — only proxy requests
- Even if a proxy token leaks, the attacker can only call pre-configured services
- Vault-server only binds to localhost (or Docker internal network)
- All proxy calls logged with: service, method, path, status, duration, token_id
- Credentials never logged, never in error messages, never in responses
- Claude runs as `uid=1001` — minimal filesystem access
- The CC never stores the master password — it only forwards it to vault-server for unlock

## Migrating existing tool credentials

If tools currently manage their own API keys (e.g., `token.json` files):

1. Open CC → Vault page → Add Service for each API
2. Test connectivity from the CC UI
3. Update tools to use `vault proxy` instead of direct API calls
4. Delete plaintext credential files from the container
5. Rotate the API keys (old ones may have been exposed)
