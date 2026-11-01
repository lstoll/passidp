# WebAuthn/Passkey OIDC Identity Provider

**Note:** This is experimental software. It is probably not stable nor secure. Don't use it in production!

See [Issues](/../../issues) for the closest thing we have to a roadmap.

## Quick Start

### 1. Generate Development Certificates

```bash
brew install mkcert
mkcert -install
mkcert -cert-file=dev-cert.pem -key-file=dev-key.pem localhost
```

### 2. Create Configuration File

Create a configuration file (e.g., `etc/config.hujson`) based on the example:

Static confidential clients can authenticate with `private_key_jwt`. Configure
either `clientJWTPublicKeys` or `jwksURL` in place of `clientSecrets`:

```json
{
  "id": "service-client",
  "redirectURLs": ["https://client.example/callback"],
  "clientJWTPublicKeys": [
    {"pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n", "kid": "current-key"}
  ]
}
```

Each PEM entry is one PKIX public key. `kid` is optional; if omitted, the
server derives an RFC 7638 SHA-256 key thumbprint. A remote keyset uses
`"jwksURL": "https://client.example/jwks.json"` instead; it must be an https
URL. The server loads it in the background, so startup doesn't wait on the
client's key host. Until the first fetch succeeds, that client's token requests
fail with `invalid_client`. The server keeps the keys refreshed and retains the
last valid keys if a refresh fails. These authentication modes cannot be combined with
`public` or `clientSecrets`.

### 3. Start the Server

On the server host:

```bash
go run ./cmd/passidp \
  --config=etc/dev-config.hujson \
  --credential-store-path=data/credentials.json \
  --state-path=data/state.sqlite \
  serve \
  --cert-file=dev-cert.pem \
  --key-file=dev-key.pem \
  --listen-addr=localhost:8085
```

### 4. Test the Auth Flow

```bash
# Test with OIDC example RP
go run lds.li/oauth2ext/cmd/oidc-example-rp@latest

# Test with OIDC CLI
go run lds.li/oauth2ext/cmd/oidccli@latest \
  -issuer=https://localhost:8085 \
  -client-id=cli \
  info
```

## Credential Management

`add-credential` writes a pending enrollment into the SQLite state database (`--state-path`). The running server stores the passkey in `credentials.json` when registration finishes.

### Adding a Credential to a User

Create a short-lived enrollment URL (15 minutes by default), then complete WebAuthn registration in the browser. The passkey is stored as soon as registration succeeds.

```bash
go run ./cmd/passidp \
  --config=etc/dev-config.hujson \
  --state-path=data/state.sqlite \
  add-credential \
  --user-id=da5b51ac-0efd-4631-8790-9f02d516527c
```

Pass `--validity=1h` to keep the URL open longer.

This will output:
```
Enrollment ID: 123e4567-e89b-12d3-a456-426614174000
Enrollment Key: 987fcdeb-51a2-43f1-9b8c-123456789abc
Valid until: 2025-01-15T10:45:00Z
Enroll at: https://localhost:8085/registration?enrollment_token=987fcdeb-51a2-43f1-9b8c-123456789abc&user_id=da5b51ac-0efd-4631-8790-9f02d516527c
```

Open the enrollment URL, name the key, and register a passkey. The server must be running so it can write the new credential.

## Development

SQL queries live in `internal/storage/queries`. sqlc reads the numbered migrations
and migration-runner bootstrap schema in `internal/storage/migrations` directly;
there is no separate schema snapshot to maintain. After changing queries or
migrations, run `go generate ./internal/storage` and commit the generated
`internal/storage/dbsql` package. The generator version is pinned in the directive.

Session and keyset persistence use their library adapters; their tables are
created by the application migrations.

### Run E2E Tests

```bash
TEST_E2E=true go test -v ./e2e -count=1 -run TestE2E
```

### Get a token
