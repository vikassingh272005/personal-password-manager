# SecureVault — zero-knowledge password manager

A personal password manager where the server never sees your data. Vault
items are encrypted and decrypted entirely in the browser; the API stores
only ciphertext.

## Architecture

- **`secure-vault/crates/`** — Rust API (axum + sqlx + PostgreSQL):
  `api` (HTTP routes, middleware), `auth`, `vault`, `crypto`, `audit`,
  `config`, `database`, `models`, `webauthn` (stub for future passkeys).
- **`secure-vault/apps/web/`** — Next.js 14 client (TypeScript, Tailwind,
  zustand): vault, generator, monitor (breach checks), devices, admin
  console, settings.
- **`secure-vault/migrations/`** — numbered sqlx migrations (001–005).

### Security model

- **Zero knowledge:** a random VEK encrypts every vault snapshot. The VEK is
  wrapped client-side by a KEK derived from your master password (PBKDF2-SHA256,
  310k iterations) — the server only ever stores wrapped keys and ciphertext.
- **Recovery:** a printable Secret Key can re-wrap the VEK; master-password
  changes re-wrap the key without re-encrypting data.
- **Two-factor (TOTP, RFC 6238):** enroll from Settings by scanning a QR code.
  Login with 2FA returns `202` and a restricted "awaiting 2FA" session that
  only accepts `/auth/2fa/challenge`; disabling requires code **and** password.
  2FA status is visible per user in the admin console.
- **Hardening:** in-memory sliding-window rate limiting on auth routes,
  CORS pinned via `CORS_ORIGINS`, HttpOnly SameSite session cookies,
  device registration, and a full audit trail.

## Quickstart

```bash
# 1. Database
cd secure-vault && docker compose up -d     # postgres on :5433

# 2. Configure
cp .env.example .env                        # set DATABASE_URL / ADMIN_EMAILS

# 3. API (listens on :3001)
cargo run -p secure-vault-api

# 4. Web (listens on :3000, proxies /api to the API)
cd apps/web && npm install && npm run dev
```

Health: `GET /health` (liveness) and `GET /ready` (migrations applied).
First account listed in `ADMIN_EMAILS` is elevated to admin at login.

## Tests & CI

```bash
cargo test --workspace                      # unit + API integration tests
cargo clippy --workspace -- -D warnings
cargo fmt --check
cd apps/web && npm run lint && npm run build
```

The integration suite (`crates/api/tests/api_flows.rs`) boots the real router
against a disposable Postgres database and exercises register → login → 2FA
enrollment → challenge → vault sync flows over HTTP.

GitHub Actions (`.github/workflows/ci.yml`) runs fmt/clippy/tests with a
Postgres service container and the Next.js lint/build on every push.

## Documentation

See [`secure-vault/README.md`](secure-vault/README.md) for the full API and
client-crypto walkthrough.
