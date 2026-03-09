# Contributing to vault-proxy

## Getting Started

```bash
git clone https://github.com/alamparelli/vault-proxy
cd vault-proxy
go build ./...
go test ./...
```

Requires Go 1.24+.

## Development

### Project Structure

```
cmd/
  vault-server/    Server binary (HTTP API + proxy)
  vault-cli/       CLI binary (human + AI agent interface)
internal/
  api/             HTTP handlers, auth middleware, proxy
  crypto/          AES-256-GCM encryption, Argon2id KDF
  oauth2/          OAuth2 refresh + service account JWT exchange
  vault/           Encrypted store, types
pkg/
  client/          Portable HTTP client (importable by any Go project)
```

### Running Tests

```bash
go test ./...
```

Tests use `httptest.NewServer` for API tests and `t.TempDir()` for vault persistence tests. No external services required.

### Adding a New Auth Type

1. Add fields to `Auth` struct in `internal/vault/types.go`
2. Add validation in `validateAuthType()` in `internal/api/services.go`
3. Add injection logic in `injectAuth()` in `internal/api/proxy.go`
4. Add tests

### Code Style

- Standard Go formatting (`gofmt`)
- No external dependencies beyond `golang.org/x/crypto` and `golang.org/x/term`
- Keep the binary self-contained — avoid adding runtime dependencies

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Ensure `go test ./...` passes
4. Submit a PR with a clear description of the change

## Reporting Issues

Open an issue at https://github.com/alamparelli/vault-proxy/issues with:
- What you expected vs what happened
- Steps to reproduce
- Go version and OS

## Security

If you find a security vulnerability, please open an issue or contact the maintainer directly rather than disclosing publicly.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
