# WebAuthn OIDC Identity Provider

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

### 3. Start the Server

On the server host:

```bash
webauthn-oidc-idp \
  --config=etc/config.hujson \
  --db-path=data/idp.db \
  serve \
  --cert-file=dev-cert.pem \
  --key-file=dev-key.pem \
  --listen-addr=localhost:8085 \
  --credential-store-path=data/credentials.json \
  --state-path=data/state.bolt \
  --admin-socket-path=data/admin.sock
```

**Note:** The `--admin-socket-path` is optional but required for credential management commands. The socket directory must exist and be writable by the server process.

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

All credential management commands must be run **on the server host** and communicate with the server via the Unix socket API. The server must be running with `--admin-socket-path` configured.

### Adding a Credential to a User

This is a two-step process to ensure security:

#### Step 1: Create Enrollment

On the server host:

```bash
webauthn-oidc-idp \
  --config=etc/config.hujson \
  add-credential \
  --user-id=da5b51ac-0efd-4631-8790-9f02d516527c
```

This will output:
```
Enrollment ID: 123e4567-e89b-12d3-a456-426614174000
Enrollment Key: 987fcdeb-51a2-43f1-9b8c-123456789abc
Enroll at: https://localhost:8085/registration?enrollment_token=987fcdeb-51a2-43f1-9b8c-123456789abc&user_id=da5b51ac-0efd-4631-8790-9f02d516527c
```

#### Step 2: User Completes Registration

1. Share the enrollment URL with the user
2. User opens the URL in a browser
3. User follows the WebAuthn registration flow to set up a passkey
4. After successful registration, the user receives a confirmation key

#### Step 3: Confirm Enrollment

On the server host, use the enrollment ID and confirmation key from Step 2:

```bash
webauthn-oidc-idp \
  --config=etc/config.hujson \
  confirm-credential \
  --user-id=da5b51ac-0efd-4631-8790-9f02d516527c \
  --enrollment-id=123e4567-e89b-12d3-a456-426614174000 \
  --confirmation-key=987fcdeb-51a2-43f1-9b8c-123456789abc
```

This activates the credential and makes it available for authentication.

### List Credentials

On the server host:

```bash
webauthn-oidc-idp \
  --config=etc/config.hujson \
  list-credentials
```

Output:
```
ID                                      Name            User ID                               User Name    User Email              Created At
123e4567-e89b-12d3-a456-426614174000   iPhone          da5b51ac-0efd-4631-8790-9f02d516527c  Dev User     dev-user@example.com   2025-01-15T10:30:00Z
```

### Delete a Credential

On the server host:

```bash
webauthn-oidc-idp \
  --config=etc/config.hujson \
  delete-credential \
  --credential-id=123e4567-e89b-12d3-a456-426614174000
```

## Development

### Run E2E Tests

```bash
TEST_E2E=true go test -v ./e2e -count=1 -run TestE2E
```
