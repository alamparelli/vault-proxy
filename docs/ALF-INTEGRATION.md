# Vault-Proxy — ALF Integration

How to integrate vault-proxy with [ALF](https://github.com/alessandrolamparelli/alf) so Claude can call APIs without seeing credentials.

## Architecture

```
┌─────────────────────────────────────┐
│ Host                                │
│                                     │
│  vault-server (127.0.0.1:8390)      │
│  ├── vault.enc (encrypted secrets)  │
│  └── admin access (vault-cli)       │
│                                     │
└───────────┬─────────────────────────┘
            │ Docker network / localhost
┌───────────▼─────────────────────────┐
│ ALF Container                       │
│                                     │
│  Claude subprocess (uid=1001)       │
│  ├── VAULT_TOKEN=<proxy-scope>      │
│  ├── VAULT_ADDR=http://host:8390    │
│  └── vault (in tools.d/, on PATH)   │
│                                     │
│  Claude runs:                       │
│    vault proxy openrouter POST \    │
│      /v1/chat/completions '...'     │
│                                     │
│  → Never sees API keys              │
│  → Can only call pre-configured     │
│    services                         │
│  → All calls logged                 │
└─────────────────────────────────────┘
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
      - VAULT_TOKEN_FILE=/run/secrets/vault_token
    extra_hosts:
      - "host.docker.internal:host-gateway"  # Linux only
    secrets:
      - vault_token

secrets:
  vault_token:
    file: ./secrets/vault_token
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
- Master password managed by the human operator
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

With sidecar, you need to unlock the vault on container start. Options:
- Unlock via Control Center UI on first boot
- Auto-unlock with password from Docker secret (less secure but convenient)

## Security Considerations

- `proxy` tokens **cannot** read or modify secrets — only proxy requests
- Even if a proxy token leaks, the attacker can only call pre-configured services
- Vault-server only binds to localhost (or Docker internal network)
- All proxy calls logged with: service, method, path, status, duration, token_id
- Credentials never logged, never in error messages, never in responses
- Claude runs as `uid=1001` — minimal filesystem access

## Migrating existing tool credentials

If tools currently manage their own API keys (e.g., `token.json` files):

1. Add each service to vault: `vault-cli service add '{"name":"...","base_url":"...","auth":{...}}'`
2. Update tools to use `vault proxy` instead of direct API calls
3. Delete plaintext credential files from the container
4. Rotate the API keys (old ones may have been exposed)
