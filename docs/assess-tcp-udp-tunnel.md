# Assessment: TCP/UDP Tunnel Option for vault-proxy SDK

**Date:** 2026-04-01
**Status:** Proposed
**Author:** Claude (automated assessment)

---

## Context

vault-proxy is a Go HTTP proxy (~7300 LOC) that injects credentials server-side.
Current transports: HTTP/HTTPS proxy, SSH (exec/SFTP/shell via WebSocket), TCP + Unix sockets.

## TCP Tunnel

**Verdict: Recommended**

### Approach

WebSocket upgrade relay, consistent with existing SSH shell pattern:

```
Client SDK --WebSocket--> vault-proxy --TCP--> destination:port
```

- New route: `GET /tunnel/{service}/connect` (WebSocket upgrade)
- Service config: `host`, `port`, `protocol: "tcp-tunnel"`
- Reuses existing SSRF-safe dialer and vault token auth

### Use Cases

| Use Case | Example |
|----------|---------|
| Databases | PostgreSQL, MySQL, Redis |
| gRPC native | Without HTTP/2 gateway |
| Mail | SMTP, IMAP |
| Custom protocols | Proprietary TCP services |

### Effort

| Component | LOC |
|-----------|-----|
| Server route + TCP relay | ~300-400 |
| Service type config | ~50 |
| Go SDK (`pkg/client`) | ~100-150 |
| Python SDK | ~100 |
| Tests | ~200-300 |
| **Total** | **~750-1000** |

### Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Expanded attack surface | Port/host allowlist per service, rate limiting |
| Long-lived connections | Idle timeout, max duration, backpressure handling |
| Scope creep (becoming a VPN) | Strict service-scoped config, no wildcard destinations |

### Optional Phase 2: Protocol-aware Auth Injection

Per-protocol credential injection (PostgreSQL startup message, MySQL handshake, Redis `AUTH`).
Decoupled from Phase 1 — tunnel works as a dumb relay first.

---

## UDP Tunnel

**Verdict: Not recommended**

| Factor | Detail |
|--------|--------|
| Complexity | Connectionless, requires multiplexing (QUIC or UDP-over-WebSocket) |
| Relevance | DNS, VoIP, gaming — not aligned with secrets management for AI agents |
| ROI | High effort, no clear use case in target domain |

Re-evaluate if a concrete UDP use case emerges.

---

## Decision Summary

| Feature | Decision | Priority |
|---------|----------|----------|
| TCP tunnel (WebSocket relay) | Go | Medium |
| Protocol-aware auth injection | Optional Phase 2 | Low |
| UDP tunnel | No-go | N/A |
