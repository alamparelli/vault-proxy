# SDK Integration Guide

## Overview

vault-proxy SDKs handle authentication, error parsing, and HTTP plumbing so you can proxy API calls in a few lines. What you get over raw HTTP:

- **Automatic token management** -- `Authorization: Bearer` header injected on every request
- **Typed responses** -- `ServiceInfo`, `TokenInfo`, `FileInfo` instead of raw JSON
- **Streaming support** -- iterate over chunked responses (SSE from LLM APIs)
- **Error handling** -- HTTP errors become typed exceptions/errors with status codes
- **File uploads** -- multipart encoding handled internally
- **Security defaults** -- Python SDK refuses plaintext HTTP to non-localhost by default

Both SDKs are thin wrappers around the vault-proxy HTTP API. No vendored dependencies beyond an HTTP client (`net/http` in Go, `httpx` in Python).

## Prerequisites

A running vault-proxy server. Pick one:

```bash
# Docker
docker run -d --name vault -p 8390:8390 -v vault-data:/data \
  ghcr.io/alamparelli/vault-proxy:latest

# Binary
./vault-server --listen 127.0.0.1:8390 --data-dir ~/.vault-proxy
```

Unlock the vault and create at least one service:

```bash
./vault-cli unlock
./vault-cli service add '{
  "name": "openrouter",
  "base_url": "https://openrouter.ai/api",
  "auth": {"type": "bearer", "token": "sk-or-v1-xxxxx"}
}'
```

Create a proxy token for your agent:

```bash
./vault-cli token create proxy
# tok_abc123... -- give this to your agent code
```

Two environment variables configure both SDKs:

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_ADDR` | `http://127.0.0.1:8390` | Server address |
| `VAULT_TOKEN` | (empty) | Auth token (admin or proxy scope) |

---

## Go SDK

### Install

```bash
go get github.com/alamparelli/vault-proxy/pkg/client
```

### Setup

```go
import "github.com/alamparelli/vault-proxy/pkg/client"

// Option 1: From environment (VAULT_ADDR + VAULT_TOKEN)
c := client.New()

// Option 2: Explicit
c := client.NewWithToken("http://127.0.0.1:8390", "tok_abc123...")
```

Both constructors return a `*Client` with a 60-second HTTP timeout.

### Proxy an API Call

```go
body := strings.NewReader(`{
    "model": "anthropic/claude-haiku-4-5",
    "messages": [{"role": "user", "content": "hello"}]
}`)

resp, err := c.Proxy("openrouter", "POST", "/v1/chat/completions", body)
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

// resp is a standard *http.Response -- read it however you want
var result map[string]any
json.NewDecoder(resp.Body).Decode(&result)
```

`Proxy()` returns the raw `*http.Response`. This is intentional -- it lets you handle streaming, large responses, or custom deserialization without the SDK getting in the way.

### List Services

```go
services, err := c.ListServices()
if err != nil {
    log.Fatal(err)
}
for _, s := range services {
    fmt.Printf("%s -> %s (%s)\n", s.Name, s.BaseURL, s.AuthType)
}
```

Returns `[]ServiceInfo` -- no secrets are exposed in this response.

### Create Proxy Tokens

```go
// Requires admin token
tokenID, err := c.CreateToken("proxy")
if err != nil {
    log.Fatal(err)
}
// tokenID is the full token string -- pass it to sub-agents
fmt.Println(tokenID)
```

Token scopes: `"admin"` (full access) or `"proxy"` (can only proxy requests and list services).

### Upload Credential Files

```go
err := c.UploadFile("google-sa-key", "/path/to/service-account.json")
if err != nil {
    log.Fatal(err)
}
```

Files are stored encrypted in the vault. Use `file_ref` in service configs to reference them.

### Streaming Responses

Since `Proxy()` returns a raw `*http.Response`, streaming works naturally:

```go
resp, err := c.Proxy("openrouter", "POST", "/v1/chat/completions", body)
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

scanner := bufio.NewScanner(resp.Body)
for scanner.Scan() {
    line := scanner.Text()
    if strings.HasPrefix(line, "data: ") {
        chunk := line[6:]
        if chunk == "[DONE]" {
            break
        }
        // Parse SSE chunk
        fmt.Print(chunk)
    }
}
```

### Error Handling

SDK methods return errors in the format `HTTP {status}: {body}`. Network errors propagate as-is.

```go
resp, err := c.Proxy("nonexistent", "GET", "/", nil)
if err != nil {
    // err.Error() == "HTTP 404: service not found"
    log.Fatal(err)
}
```

For `Proxy()` specifically, you get the raw response -- check `resp.StatusCode` yourself:

```go
resp, err := c.Proxy("openrouter", "POST", "/v1/chat/completions", body)
if err != nil {
    log.Fatal(err) // connection-level error
}
defer resp.Body.Close()

if resp.StatusCode >= 400 {
    body, _ := io.ReadAll(resp.Body)
    log.Fatalf("upstream error %d: %s", resp.StatusCode, body)
}
```

### Full Working Example

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "log"
    "os"

    "github.com/alamparelli/vault-proxy/pkg/client"
)

func main() {
    c := client.NewWithToken(
        os.Getenv("VAULT_ADDR"),
        os.Getenv("VAULT_TOKEN"),
    )

    // Check server health
    status, err := c.Health()
    if err != nil {
        log.Fatal(err)
    }
    if status != "unlocked" {
        log.Fatal("vault is locked")
    }

    // Build request
    reqBody, _ := json.Marshal(map[string]any{
        "model": "anthropic/claude-haiku-4-5",
        "messages": []map[string]string{
            {"role": "user", "content": "What is vault-proxy?"},
        },
    })

    // Proxy through vault -- credentials injected server-side
    resp, err := c.Proxy("openrouter", "POST", "/v1/chat/completions", bytes.NewReader(reqBody))
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()

    var result map[string]any
    json.NewDecoder(resp.Body).Decode(&result)
    fmt.Println(result)
}
```

---

## Python SDK

### Install

```bash
pip install vault-proxy
```

Requires Python 3.10+. The only dependency is `httpx`.

### Setup

```python
from vault_proxy import VaultClient

# Option 1: From environment (VAULT_ADDR + VAULT_TOKEN)
client = VaultClient()

# Option 2: Explicit
client = VaultClient(addr="http://127.0.0.1:8390", token="tok_abc123...")
```

The client has a 60-second default timeout (configurable via `timeout` parameter).

**Security**: The Python SDK refuses plaintext HTTP to non-localhost addresses by default. Override with `allow_insecure=True` if needed.

### Context Manager

The client wraps an `httpx.Client` that holds a connection pool. Use it as a context manager to ensure cleanup:

```python
with VaultClient() as client:
    resp = client.proxy("openrouter", "POST", "/v1/chat/completions", json=body)
    print(resp.json())
# Connection pool closed here
```

Or close manually:

```python
client = VaultClient()
try:
    # ... use client ...
finally:
    client.close()
```

### Proxy an API Call

```python
resp = client.proxy("openrouter", "POST", "/v1/chat/completions", json={
    "model": "anthropic/claude-haiku-4-5",
    "messages": [{"role": "user", "content": "hello"}],
})
print(resp.json())
```

`proxy()` returns a standard `httpx.Response`. The `json` kwarg serializes the dict automatically.

You can also pass raw bytes with `data=`:

```python
resp = client.proxy("some-service", "POST", "/endpoint", data=b"raw bytes")
```

Or extra headers:

```python
resp = client.proxy("anthropic", "POST", "/v1/messages",
    json=body,
    headers={"anthropic-version": "2023-06-01"},
)
```

### List Services

```python
services = client.list_services()
for s in services:
    print(f"{s.name} -> {s.base_url} ({s.auth_type})")
```

Returns a list of `ServiceInfo` dataclasses.

### Create Proxy Tokens

```python
# Requires admin token
token_id = client.create_token("proxy")
print(token_id)  # Full token string -- pass to sub-agents
```

### Upload Credential Files

```python
client.upload_file("google-sa-key", "/path/to/service-account.json")
```

Accepts `str` or `pathlib.Path`.

### Streaming with proxy_stream()

`proxy_stream()` returns a generator that yields bytes as they arrive. Ideal for LLM streaming (SSE):

```python
body = {
    "model": "anthropic/claude-haiku-4-5",
    "messages": [{"role": "user", "content": "hello"}],
    "stream": True,
}

for chunk in client.proxy_stream("openrouter", "POST", "/v1/chat/completions", json=body):
    print(chunk.decode(), end="", flush=True)
```

Under the hood this uses `httpx`'s streaming response with `iter_bytes()`. The connection is held open for the duration of iteration and cleaned up when the generator exits.

### Error Handling

All methods raise `VaultError` on HTTP 4xx/5xx:

```python
from vault_proxy import VaultClient, VaultError

try:
    resp = client.proxy("nonexistent", "GET", "/")
except VaultError as e:
    print(e.status_code)  # 404
    print(e.message)      # "service not found"
```

`VaultError` has two attributes:
- `status_code` -- the HTTP status code
- `message` -- the response body text

### Unlock from Code

The Python SDK auto-sets the token after unlocking:

```python
client = VaultClient()
token = client.unlock("my-master-password")
# client.token is now set -- no need to pass it again
services = client.list_services()
```

`lock()` clears the token:

```python
client.lock()
# client.token is now ""
```

### Full Working Example

```python
from vault_proxy import VaultClient, VaultError

def main():
    with VaultClient() as client:
        # Check health
        status = client.health()
        if status != "unlocked":
            raise SystemExit("vault is locked")

        # List available services
        for svc in client.list_services():
            print(f"  {svc.name}: {svc.base_url}")

        # Call an LLM API through the proxy
        resp = client.proxy("openrouter", "POST", "/v1/chat/completions", json={
            "model": "anthropic/claude-haiku-4-5",
            "messages": [{"role": "user", "content": "What is vault-proxy?"}],
        })

        data = resp.json()
        print(data["choices"][0]["message"]["content"])

if __name__ == "__main__":
    main()
```

---

## Patterns

### Agent Bootstrap

Typical flow for an orchestrator that spawns AI agents:

1. Orchestrator holds an admin token
2. Orchestrator creates a scoped proxy token
3. Orchestrator passes `VAULT_ADDR` + `VAULT_TOKEN` to the agent subprocess
4. Agent uses the SDK with `New()` / `VaultClient()` -- picks up env vars automatically
5. Orchestrator revokes the token when the agent finishes

**Go:**

```go
// Orchestrator (admin)
admin := client.NewWithToken(addr, adminToken)
proxyToken, _ := admin.CreateToken("proxy")

// Spawn agent with scoped token
cmd := exec.Command("./my-agent")
cmd.Env = append(os.Environ(),
    "VAULT_ADDR="+addr,
    "VAULT_TOKEN="+proxyToken,
)
cmd.Run()

// Cleanup
admin.RevokeToken(proxyToken)
```

**Python:**

```python
import subprocess
import os

admin = VaultClient(addr=addr, token=admin_token)
proxy_token = admin.create_token("proxy")

# Spawn agent with scoped token
env = os.environ | {"VAULT_ADDR": addr, "VAULT_TOKEN": proxy_token}
subprocess.run(["python", "my_agent.py"], env=env)

# Cleanup
admin.revoke_token(proxy_token)
```

### Multi-Agent Pattern

One admin client, multiple agents each with their own proxy token. Tokens are isolated -- revoking one doesn't affect others.

```python
admin = VaultClient(addr=addr, token=admin_token)

agents = {}
for name in ["researcher", "writer", "reviewer"]:
    token = admin.create_token("proxy")
    agents[name] = token

# Each agent gets its own token
researcher = VaultClient(addr=addr, token=agents["researcher"])
writer = VaultClient(addr=addr, token=agents["writer"])

# When done, revoke all
for token in agents.values():
    admin.revoke_token(token)
```

Proxy tokens can call any configured service but cannot:
- Read or modify secrets
- Create or revoke tokens
- Add, remove, or update services
- Upload or download files

### Error Handling Best Practices

**Distinguish vault errors from upstream errors.** A 401 from vault-proxy means your token is bad. A 401 in a proxied response means the service's credentials are bad.

```python
try:
    resp = client.proxy("openrouter", "POST", "/v1/chat/completions", json=body)
except VaultError as e:
    if e.status_code == 401:
        # Your vault token is invalid or expired
        handle_auth_error()
    elif e.status_code == 404:
        # Service not found in vault
        handle_missing_service()
    else:
        raise

# If we get here, the request reached the upstream API.
# Check the upstream response status:
if resp.status_code == 429:
    # Rate limited by OpenRouter, not by vault
    handle_rate_limit(resp)
```

**Check health before making assumptions:**

```python
status = client.health()
if status == "locked":
    # Vault is locked -- either unlock programmatically or fail fast
    raise SystemExit("vault is locked -- run vault-cli unlock")
```

**Token expiry.** Tokens have a TTL (default 24h). If your agent is long-running, handle 401s by requesting a new token from the orchestrator or re-unlocking.

---

## Any Language (Raw HTTP)

The vault-proxy API is plain HTTP + JSON. No SDK required.

### Authentication

Every request (except `/health` and `/auth/unlock`) needs a Bearer token:

```
Authorization: Bearer tok_abc123...
```

### Unlock

```bash
curl -s -X POST http://127.0.0.1:8390/auth/unlock \
  -H "Content-Type: application/json" \
  -d '{"password": "my-master-password"}'
# {"id": "tok_admin_xxx..."}
```

### List Services

```bash
curl -s http://127.0.0.1:8390/services \
  -H "Authorization: Bearer $VAULT_TOKEN"
# [{"name":"openrouter","base_url":"https://openrouter.ai/api","auth_type":"bearer"}, ...]
```

### Proxy a Request

The core operation. Your request body is forwarded to the upstream service with credentials injected:

```bash
curl -s -X POST http://127.0.0.1:8390/proxy/openrouter/v1/chat/completions \
  -H "Authorization: Bearer $VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "anthropic/claude-haiku-4-5",
    "messages": [{"role": "user", "content": "hello"}]
  }'
```

URL structure: `/proxy/{service_name}/{upstream_path}`

The vault strips your `Authorization` header and injects the service's real credentials before forwarding.

### Streaming

Same endpoint, just read the response as a stream. With curl:

```bash
curl -s -N -X POST http://127.0.0.1:8390/proxy/openrouter/v1/chat/completions \
  -H "Authorization: Bearer $VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "anthropic/claude-haiku-4-5",
    "messages": [{"role": "user", "content": "hello"}],
    "stream": true
  }'
```

The `-N` flag disables output buffering so you see chunks as they arrive.

### Create a Proxy Token

```bash
curl -s -X POST http://127.0.0.1:8390/tokens \
  -H "Authorization: Bearer $VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scope": "proxy"}'
# {"id": "tok_proxy_xxx..."}
```

### Upload a File

```bash
curl -s -X POST http://127.0.0.1:8390/files \
  -H "Authorization: Bearer $VAULT_TOKEN" \
  -F "name=google-sa-key" \
  -F "file=@service-account.json"
```

### Error Responses

All errors return JSON with an HTTP status code:

```json
{"error": "unauthorized"}
```

| Status | Meaning |
|--------|---------|
| 401 | Invalid or missing token |
| 403 | Token scope insufficient (e.g., proxy token trying admin operations) |
| 404 | Service or resource not found |
| 423 | Vault is locked |
| 500 | Server error |
