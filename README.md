# SecureVault — a zero-knowledge password manager

SecureVault is a personal password manager where **the server never sees your data**. Every vault
is encrypted and decrypted entirely in the browser (Web Crypto): the Rust API authenticates you,
stores ciphertext and wrapped keys, and enforces access control — but it never possesses the key
material needed to read your passwords. If the database leaks, an attacker gets AES-256-GCM
ciphertext and Argon2id hashes, nothing usable.

It is built as a monorepo: a **Rust workspace** (axum + SQLx + PostgreSQL API) and a **Next.js 14**
web client, with Docker for local infrastructure and GitHub Actions CI.

> **Status:** production-track personal project (v0.1.0). The cryptographic core, auth, 2FA, passkeys,
> vault sync and admin console are implemented and tested; a one-host production deployment stack
> (Docker Compose + Caddy TLS + backups) and the previously-placeholder data flows (encrypted
> export/import, account deletion) are now implemented as well. Remaining known gaps are listed in
> [Limitations](#limitations).

---

## Overview

| Question | Answer |
|---|---|
| What is it? | A zero-knowledge (end-to-end encrypted) password manager with a Rust API and a Next.js web client. |
| What problem does it solve? | Cloud password managers that *can* decrypt your vault put your passwords one breach away from public. SecureVault architecturally cannot read your vault — even its own operator can't. |
| Who is it for? | Developers and security-conscious users; also a reference implementation of client-side key ceremony + zero-knowledge sync. |
| What makes it interesting? | A real two-layer key hierarchy (KEK wraps a random VEK), printable Secret-Key recovery, TOTP 2FA with restricted half-sessions, full WebAuthn passkey verification with hand-rolled minimal CBOR/COSE, and a versioned encrypted sync protocol with conflict resolution. |

---

## Features

### Vault & cryptography (implemented)

- **Zero-knowledge vault sync** — the browser derives a Key Encryption Key (KEK) from your master
  password (PBKDF2-SHA256, 310,000 iterations, per-account salt), generates a random 32-byte Vault
  Encryption Key (VEK), and uploads only: the encrypted item envelope, the KEK-wrapped VEK, and a
  Secret-Key-wrapped VEK. The master password never leaves the tab.
- **Printable Secret Key recovery** — a 32-character Crockford-base32 key (160 bits, shown as 4
  groups of 8) wraps the same VEK under an independent key. Lost master password? Unlock with the
  Secret Key and set a new one. Input normalization forgives `I/L→1`, `O→0`, case and separators.
- **Master password change without re-encryption** — only the VEK wraps are re-created; the item
  ciphertext never changes. (Legacy vaults are migrated to the random-key hierarchy on the next
  master-password change.)
- **Tamper detection** — AES-256-GCM authenticated encryption everywhere; a wrong master password
  or Secret Key fails at the GCM unwrap, client-side, before anything is sent.
- **Domain separation** — KEK wraps and recovery wraps carry distinct AES-GCM additional-data tags
  (`SecureVault:v1:kek` / `SecureVault:v1:recovery`), so one blob can't be replayed as the other.

### Authentication (implemented)

- **Accounts** — email + account password (distinct from the vault master password); server-side
  Argon2id hashing; sessions are 64-char random tokens stored **hashed** (SHA-256) with a 24 h
  expiry, delivered as `HttpOnly; SameSite=Lax` cookies, revocable individually or all at once.
- **TOTP two-factor (RFC 6238)** — enroll from Settings by scanning a QR code. Password login on a
  2FA account returns **`202`** and a restricted *awaiting-2FA* session that only the
  `/auth/2fa/challenge` endpoint accepts. Disabling 2FA requires both a current code **and** the
  account password.
- **Passkeys / WebAuthn** — register a platform passkey (Touch ID, Windows Hello, security key)
  from Settings, then use **"Sign in with passkey"** for passwordless sign-in. Server-side
  verification covers CBOR attestation parsing (`none` and `packed` self-attestation), COSE keys
  (ES256 + RS256), challenge/origin/RP-ID-hash binding, user-presence flag, mandatory user
  verification (UV), and signature-counter replay protection. Usernameless (discoverable-credential)
  login is supported; a verified assertion mints a full session.
- **Roles** — `user` / `admin` per account, re-read from the database on **every** request, so
  demotions and session revocations take effect immediately.

### Vault tools (implemented)

- **Password generator** — client-side via `crypto.getRandomValues`, charset toggles, strength meter.
- **Security Center** — local analysis of vault items (weak / reused / missing passwords, overall
  score /100). Nothing is sent to the server.
- **Breach monitor** — password checks use HIBP Pwned Passwords **k-anonymity** (only a 5-char
  SHA-1 prefix leaves the browser); email checks use the keyless XposedOrNot API. Your vault
  contents and keys are never shared with either service.
- **Auto-lock** — vault locks after a configurable inactivity timeout in minutes (default 15,
  0 = never); keys are dropped from memory.
- **Clipboard hygiene** — copied passwords are cleared from the clipboard after 30 seconds.
- **Search, folders, favorites, item types** — logins, cards, and notes with per-item detail pages.

### Administration (implemented)

- **Admin console** (`/admin`) — Overview stats (users, sessions, devices, vault syncs, recent
  events), User & Access management (promote/demote, revoke sessions), and a paginated, filterable
  Audit Log. Admins see metadata and activity — **never** vault contents.
- **Audit trail** — every meaningful action is recorded (`LOGIN_SUCCESS`, `LOGIN_FAILED`,
  `LOGIN_PASSKEY`, `LOGOUT`, `USER_REGISTERED`, `VAULT_UPDATED`, `DEVICE_ADDED`/`DEVICE_REVOKED`,
  `PASSKEY_REGISTERED`/`PASSKEY_REVOKED`, `TWO_FACTOR_*`, `ADMIN_ROLE_CHANGED`,
  `ADMIN_SESSIONS_REVOKED`) with optional JSON metadata.

### Hardening (implemented)

- In-memory fixed-window **rate limiting** on auth routes (login 10/min/IP, register 5/5 min/IP),
  keyed by `X-Forwarded-For` (bucketing only) or socket address.
- **CORS** pinned via `CORS_ORIGINS` (credentialed, explicit allow-list; empty or `*` = permissive dev mode).
- Version-conflict protection on vault uploads (`409` on stale versions) plus a unique
  `(user_id, version)` index as defense in depth.

---

## Technology stack

| Layer | Technology |
|---|---|
| Backend language | Rust 2021 (MSRV 1.75), tokio async runtime |
| HTTP framework | axum 0.7 (+ tower, tower-http: CORS, tracing) |
| Database | PostgreSQL 16 (Docker) |
| DB access | SQLx 0.8 (compile-time pool, `sqlx::migrate!` at startup) |
| Server crypto | argon2, aes-gcm, hkdf, sha2, p256, rsa, rand (OsRng), zeroize |
| 2FA | Hand-rolled TOTP (RFC 6238) in `crates/crypto` |
| Passkeys | Hand-rolled WebAuthn subset in `crates/webauthn` (CBOR/COSE, ES256/RS256) |
| Frontend framework | Next.js 14 (App Router), React 18, TypeScript 5.3 |
| Styling | Tailwind CSS 3.4 + CSS-variable design tokens |
| State | zustand (vault, auth, auto-lock stores) |
| Icons / QR | lucide-react, qrcode |
| Linting | ESLint 8 (+ eslint-config-next), cargo clippy (`-D warnings`), cargo fmt |
| Testing | `cargo test` (unit + HTTP integration against real Postgres), WebAuthn ceremony tests |
| CI/CD | GitHub Actions (fmt, clippy, tests with a Postgres service container, Next.js lint + build) |
| Package managers | Cargo, npm (Node 20 in CI) |

---

## Architecture

```mermaid
flowchart TD
    U[User's browser] -->|"/api/* rewritten by next.config.js"| W["Next.js web app (apps/web, :3000)"]
    W -->|"Web Crypto: PBKDF2 → KEK, AES-256-GCM envelope"| W
    W -->|HTTPS/HTTP JSON + session cookie| A["Axum API (crates/api, :3001)"]
    A -->|rate limiting, auth extractor, roles| A
    A -->|SQLx| DB[(PostgreSQL 16)]
    A -->|HIBP/XposedOrNot calls happen in the browser, not here| X[External breach APIs]
```

- **Web client** (`secure-vault/apps/web`) owns all key material and all encryption/decryption.
  The server stores only ciphertext, wrapped keys, and KDF parameters.
- **API** (`secure-vault/crates`) enforces authentication, roles, rate limits, versioned vault
  uploads, and the audit trail.
- **PostgreSQL** persists accounts, wrapped keys, versioned encrypted snapshots, devices,
  passkeys, sessions, and audit events. Migrations run automatically at API startup.

### Key hierarchy

```mermaid
flowchart TD
    MP["Master password (never transmitted)"] -->|PBKDF2-SHA256, 310k iters, per-user salt| KEK["Key Encryption Key"]
    SK["Secret Key (32-char Crockford base32, printed once)"] -->|PBKDF2-SHA256, fixed app salt| RK["Recovery wrapping key"]
    VEK["Random 32-byte Vault Encryption Key"] -->|AES-256-GCM| ENV["Encrypted item envelope"]
    KEK -->|AES-256-GCM, AAD 'SecureVault:v1:kek'| KW["kek_wrap (stored server-side)"]
    RK -->|AES-256-GCM, AAD 'SecureVault:v1:recovery'| RW["recovery_wrap (stored server-side)"]
    KW -.-> VEK
    RW -.-> VEK
```

Changing the master password re-wraps the VEK (both wraps) without touching the encrypted items;
unlocking with the Secret Key re-wraps the VEK under a fresh master password.

---

## Project structure

```text
secure-vault/
├── crates/                    Rust workspace (one responsibility per crate)
│   ├── api/                   Axum server: routes, auth extractor, rate limiting, errors, tests
│   ├── auth/                  Session create/validate/revoke, password authenticate
│   ├── crypto/                Argon2id, AES-256-GCM, HKDF, hashing, TOTP, generator (unit-tested)
│   ├── vault/                 VaultEngine: encrypt/decrypt/re-wrap vault documents (unit-tested)
│   ├── database/              Connection-pool helpers
│   ├── models/                Shared serde structs (User, Vault, Session, AuditEvent, …)
│   ├── webauthn/              Full WebAuthn verification (CBOR/COSE) + ceremony tests
│   ├── audit/                 Audit-event insertion
│   └── config/                AppConfig from environment
├── apps/
│   ├── web/                   Next.js 14 client (TypeScript + Tailwind)
│   │   ├── app/               Routes: /, login, register, unlock, dashboard, vault (+new/[id]),
│   │   │                      generator, security, monitor, devices, settings, admin (+users/audit)
│   │   ├── components/        Sidebar, VaultItemCard, PasswordGenerator, admin/*, SyncStatus, …
│   │   ├── hooks/             useVault (zustand), useAuth, useAutoLock, useVaultSync (auto-upload)
│   │   └── lib/               api.ts (typed client), crypto.ts, vaultKeys.ts, vaultEnvelope.ts,
│   │                          passkeys.ts, breaches.ts
│   ├── desktop/               Empty Tauri scaffold (not implemented)
│   └── mobile/                Empty scaffold (not implemented)
├── migrations/                001–005, applied automatically at API startup
├── scripts/                   dev.mjs (one-command launcher), seed-demo.mjs (demo account)
├── docs/                      api.md, architecture.md, crypto.md, deployment.md, threat-model.md
├── tests/                     Empty scaffolding (integration/crypto/security)
├── docker-compose.yml         PostgreSQL 16 (+ a Redis container the app does not use yet)
├── start-all.ps1              Legacy Windows launcher (see caveats below)
└── .env.example               Environment template
```

---

## How it works

### Registration

1. The browser generates a random 32-byte VEK and a printable Secret Key (shown **once**).
2. The master password derives the KEK locally (PBKDF2-SHA256, salt + iteration count from the
   server's `POST /auth/register` response).
3. The VEK is wrapped twice (KEK wrap + recovery wrap). The server receives: email, Argon2id
   account-password hash, KDF parameters, and the two wrapped keys — never the passwords or the VEK.

### Unlock & sync

1. `GET /api/v1/vault` returns KDF params, the latest snapshot (ciphertext + nonce), and the wraps.
2. The client derives the KEK, unwraps the VEK (GCM failure ⇒ wrong password), decrypts the
   envelope, and populates the in-memory vault.
3. Every local change is re-encrypted and uploaded (debounced ~600 ms) as `version + 1`. A `409`
   conflict means another device won — the client reloads the newer server copy automatically.
4. Locking drops keys from memory; auto-lock triggers on inactivity.

### Authentication flows

- **Password (+ TOTP when enabled):** login returns `200` (or `202` + restricted awaiting-2FA
  session → `/auth/2fa/challenge` completes it).
- **Passkey:** `/auth/passkeys/login/options` (empty body = usernameless) → browser ceremony →
  `/auth/passkeys/login/finish` verifies the assertion server-side and mints a full session.
  The vault itself still needs the master password or Secret Key — a passkey proves the *account*,
  not the *vault*.

### Admin actions

Role changes and session revocations are guarded (no self-role-change, the last admin cannot be
demoted), take effect on the victim's very next request, and are themselves audit-logged with
actor + target.

---

## Database

PostgreSQL 16; migrations `secure-vault/migrations/001–005.sql` run automatically at API startup.
All foreign keys cascade deletes to children. UUID primary keys (`uuid_generate_v4`).

```mermaid
erDiagram
    USERS ||--o| VAULTS : "one vault per user"
    USERS ||--o{ SESSIONS : "has"
    USERS ||--o{ DEVICES : "registers"
    USERS ||--o{ PASSKEYS : "registers"
    USERS ||--o{ VAULT_SNAPSHOTS : "syncs"
    USERS ||--o{ AUDIT_EVENTS : "generates"
    DEVICES ||--o{ SESSIONS : "optionally binds"
```

| Table | Purpose | Notable columns |
|---|---|---|
| `users` | Accounts | `email` (unique), `password_hash`, `role` (`user`/`admin`, CHECK-constrained), `totp_secret`, `totp_enabled` |
| `vaults` | One per user | KDF params (`PBKDF2-SHA256`, iterations, salt), `encrypted_vault_key`, `kek_wrap_*`, `recovery_wrap_*`, `version` |
| `vault_snapshots` | Sync history | `version`, `nonce`, `blob_size`, `ciphertext`; unique index on `(user_id, version)` |
| `devices` | Registered devices | `name`, `device_type`, `public_key`, `revoked_at` |
| `passkeys` | WebAuthn credentials | `credential_id` (unique), COSE `public_key`, `sign_count` |
| `sessions` | Login sessions | `token_hash` (SHA-256, unique), `device_id`, `expires_at`, `awaiting_2fa` |
| `audit_events` | Event log | `event_type`, `metadata` (JSONB), `ip_hash` (not populated yet), indexed by `created_at DESC` |

Note: the TOTP secret is stored reversibly by design — the server must compute expected codes at
login. It is independent of the vault keys, so its leak would not expose vault contents.

---

## API documentation

Base URL: `http://localhost:3001/api/v1` (the web app reaches it via the `/api/*` rewrite).
Errors are JSON `{ "error": "..." }` with meaningful status codes (401/403/404/400/409/429/500).

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| GET | `/health`, `/ready` | — | Liveness / readiness (migrations applied) |
| POST | `/auth/register` | — | Create account + vault (rate-limited 5/5 min/IP) |
| POST | `/auth/login` | — | Create session; `202` when 2FA is enabled (10/min/IP) |
| POST | `/auth/2fa/challenge` | awaiting-2FA session | Complete TOTP login |
| POST | `/auth/2fa/setup`, `/auth/2fa/verify`, `/auth/2fa/disable` | ✅ | Enroll / confirm / disable (disable needs code + password) |
| POST | `/auth/passkeys/register/options` · `/finish` | ✅ | Register a passkey |
| POST | `/auth/passkeys/login/options` · `/finish` | — | Passkey sign-in (usernameless supported) |
| GET / DELETE | `/auth/passkeys`, `/auth/passkeys/:passkey_id` | ✅ | List / revoke passkeys |
| POST | `/auth/logout` | ✅ | Revoke all of the user's sessions |
| GET / POST | `/auth/refresh`, `/auth/me` | ✅ | Session validation / identity + role + 2FA status |
| DELETE | `/account` | ✅ (+ password) | Permanently delete the caller's account & data (audited, tombstoned trail) |
| DELETE | `/admin/users/:user_id/account` | admin | Admin-initiated account deletion (never the last admin / self) |
| GET / PUT | `/vault` | ✅ | Fetch / upload encrypted vault (version conflict ⇒ `409`) |
| PUT | `/vault/keys` | ✅ | Re-upload key wraps (master-password change, recovery) |
| GET / POST | `/devices` | ✅ | List / register devices |
| DELETE | `/devices/:device_id` | ✅ | Revoke a device (and its sessions) |
| GET | `/items` | ✅ | Placeholder — item operations are client-side on the encrypted vault |
| GET | `/admin/overview` | admin | Totals + 15 most recent audit events |
| GET | `/admin/users` | admin | All accounts with activity counts + 2FA status |
| PATCH | `/admin/users/:user_id/role` | admin | Promote/demote (guarded) |
| POST | `/admin/users/:user_id/revoke-sessions` | admin | Force sign-out everywhere |
| GET | `/admin/audit` | admin | Paginated, filterable audit feed (`limit` ≤ 200, `offset`, `event_type`, `user_id`) |

Example — vault upload:

```json
PUT /api/v1/vault
{
  "version": 7,
  "ciphertext": "<base64 AES-256-GCM envelope>",
  "nonce": "<base64 12-byte IV>",
  "kek_wrap":      { "ciphertext": "<base64>", "nonce": "<base64>" },
  "recovery_wrap": { "ciphertext": "<base64>", "nonce": "<base64>" }
}
```

Full request/response reference: [`secure-vault/docs/api.md`](secure-vault/docs/api.md).

---

## Prerequisites

- **Docker** (PostgreSQL 16 container)
- **Rust** 1.75+ with Cargo
- **Node.js** 20 (what CI uses; no `engines` pin) + npm
- Windows works out of the box (`scripts/dev.mjs` can even start Docker Desktop for you);
  macOS/Linux are supported by the same scripts except `start-all.ps1`.

## Installation

```bash
git clone <your-repo-url>
cd <repo-root>
npm install          # root convenience scripts
```

## Environment variables

Copy the template: `cp secure-vault/.env.example secure-vault/.env`

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgres://postgres:postgres@localhost:5432/secure_vault` | SQLx pool target (the dev launcher overrides this to port **5433**) |
| `PORT` | `3001` | API bind port |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated credentialed origins; empty or `*` = permissive |
| `ADMIN_EMAILS` | *(empty)* | Comma-separated emails granted `admin` at register/login; empty in **development** ⇒ first registered account becomes admin. Empty in **production** ⇒ bootstrap disabled (promote via SQL — see deployment docs) |
| `WEBAUTHN_RP_ID` | `localhost` | Passkey relying-party ID (set to your domain in production) |
| `WEBAUTHN_ORIGIN` | `http://localhost:3000` | Exact origin allowed in WebAuthn ceremonies |
| `SESSION_SECRET` | `change-me-in-production` | **Reserved, currently unused** |
| `APP_ENV` | `development` | `production` forces Secure cookies and disables the first-admin bootstrap |
| `COOKIE_SECURE` | *(empty)* | Secure-cookie override; default is on in production, off otherwise |
| `SNAPSHOT_RETENTION_COUNT` | `20` | Encrypted snapshots kept per user (hourly cleanup; newest always kept; 0 = keep all) |
| `AUDIT_IP_SALT` | *(empty)* | Salt for salted-SHA-256 client-IP hashes in the audit log (raw IPs are never stored) |

Never commit real `.env` values. The seeded demo credentials below are for local development only.

## Running locally

### One command (recommended)

```bash
npm run dev
```

`secure-vault/scripts/dev.mjs` is idempotent and: ensures Docker is up (starts Docker Desktop on
Windows/macOS if needed), creates/starts a Postgres 16 container on **:5433**,
builds + starts the API on **:3001**, builds (`next build`) + starts the web app on **:3000**,
and seeds the demo account. Flags: `--no-seed`, `--no-web`, `--rebuild-web`. Logs land in
`secure-vault/.dev-run/`.

Then open **http://localhost:3000**. Demo login:

| What | Value |
|---|---|
| Email | `demo@securevault.local` |
| Account password | `demo-password-123` |
| Master password | `demo-master-456` |
| Secret Key | printed once by the seeder — copy it somewhere safe |

The seed runs the real client-side key ceremony (Node WebCrypto), so the demo vault is a genuine
zero-knowledge vault. `npm run seed` re-runs it; note `--reset` cannot fully reset — see
[Limitations](#limitations).

### Manual steps

```bash
# 1. Database (compose default maps 5432)
cd secure-vault && docker compose up -d

# 2. Configure
cp .env.example .env

# 3. API on :3001
cargo run -p secure-vault-api

# 4. Web on :3000 (rewrites /api/* to localhost:3001)
cd apps/web && npm install && npm run dev
```

Health checks: `GET http://localhost:3001/health` and `GET /ready`.

### Windows legacy launcher

`secure-vault/start-all.ps1` starts everything but has machine-specific default paths, defaults
the backend to port **8080** (which breaks the web app's `/api` rewrite targeting :3001), and uses
compose's :5432 database. Prefer `npm run dev`; if you use the script, pass
`-BackendPort 3001` and matching `-DatabaseUrl`.

### Production build

```bash
npm run build    # cargo build --workspace + next build
```

### Production deployment

A one-host production stack ships in-repo: `docker-compose.prod.yml` runs
Caddy (automatic Let's Encrypt HTTPS) → the Next.js web container → the Rust
API container → PostgreSQL, with secrets in a host-only `.env.prod`, an SSH
deploy workflow (`.github/workflows/deploy.yml`), and backup/restore scripts
(`docker/backup-db.sh`, `docker/restore-db.sh`). Full runbooks:
[`secure-vault/docs/deployment.md`](secure-vault/docs/deployment.md) and
[`secure-vault/docs/operations.md`](secure-vault/docs/operations.md).
Security-relevant decisions are recorded as ADRs under
[`secure-vault/docs/adr/`](secure-vault/docs/adr/).

---

## Development workflow

Root scripts (see `package.json`):

| Command | What it does |
|---|---|
| `npm run dev` | Full stack + demo seed (see above) |
| `npm run seed` | Re-seed the demo account |
| `npm run test` | `cargo test --workspace` |
| `npm run lint` | `cargo clippy -D warnings` + `next lint` |
| `npm run build` | Rust release-style build + Next.js production build |

## Testing

```bash
# Rust unit tests (crypto, TOTP, auth, vault, rate limiter, WebAuthn ceremonies)
cargo test --workspace --manifest-path secure-vault/Cargo.toml

# API integration tests (boot the real router against a disposable Postgres)
# The suite TRUNCATES the database it connects to. Point it at a disposable DB:
SECURE_VAULT_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5433/secure_vault_test \
cargo test --workspace --manifest-path secure-vault/Cargo.toml

# Web
cd secure-vault/apps/web && npm run lint && npm run build
```

The integration suite (`crates/api/tests/api_flows.rs`) exercises over plain HTTP:
register → duplicate-register rejection → identity → vault version conflicts (`409`) → admin role
gating (`403`) → first-user-becomes-admin bootstrap (and its **absence in production mode**) →
2FA enrollment → `202` half-session → challenge → full session → guarded 2FA disable →
account deletion (password-gated, cascade, tombstoned audit trail) → snapshot retention pruning →
request-body-limit enforcement. CI runs all of this against a Postgres service container on every
push/PR. A weekly `Security audit` workflow runs `cargo audit` + `npm audit`.

## CI/CD

`.github/workflows/ci.yml` runs on push/PR:

- **Rust job** — `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` against a disposable Postgres 16 service container.
- **Web job** — `npm ci`, `npm run lint`, `npm run build` on Node 20.

---

## Authentication & authorization summary

- Two distinct secrets: the **account password** (server-verifiable, Argon2id) and the **master
  password** (never transmitted, unlocks the vault).
- Sessions: 24 h, HttpOnly cookie with `Secure` forced in production, token stored SHA-256-hashed,
  revocable (logout = all your sessions; admins can revoke anyone's).
- Login responses are timing-equalized (unknown emails still burn an Argon2id verification) and
  login/register/passkey/2FA-challenge endpoints are rate-limited per IP.
- Roles re-read from the DB on every request; admin routes additionally call `ensure_admin` (`403`).
- Admin bootstrap: list emails in `ADMIN_EMAILS`. In development an empty list also makes the
  **first registered account** admin; in production that bootstrap is **disabled** — promote an
  existing account explicitly:

  ```sql
  UPDATE users SET role = 'admin' WHERE email = 'you@example.com';
  ```

- Account deletion (self-service with password confirmation, or admin-initiated) is immediate,
  cascades all user data in one transaction, and re-points audit events to a tombstone account so
  the audit trail outlives deleted users.
- Rate limits: login-class 10/min/IP (login, passkey login, TOTP challenge), register 5/5 min/IP
  (in-memory; a multi-instance deployment should move counters to Redis — see ADR 0004).

## Configuration

Everything configurable lives in `secure-vault/.env` (see
[Environment variables](#environment-variables)); the web app's only runtime coupling is the
`/api/* → http://localhost:3001` rewrite in `apps/web/next.config.js` — change both together if
you move the API.

## Frontend

- **Routes:** `/` landing · `/register` · `/login` (password or passkey) · `/unlock` (master
  password **or** Secret Key) · `/dashboard` · `/vault` (+ `/new`, `/[id]`) · `/generator` ·
  `/security` · `/monitor` · `/devices` · `/settings` · `/admin` (+ `/users`, `/audit`).
- **State:** zustand stores (`useVault`: items/folders/lock/sync state; `useAuth`: identity/role);
  `useVaultSync` is the single owner of persistence; `useAutoLock` watches activity events.
- **Design:** dark-first tokens in `styles/globals.css` (`.card`, `.btn-primary`, …) composed with
  Tailwind utilities.
- **Settings page:** master-password change, Secret Key display/regenerate, passkey management,
  TOTP enrollment via QR code, auto-lock timeout. Export/import/delete-account are placeholders.

## Backend

- Boot sequence (`crates/api/src/main.rs`): load `AppConfig` → connect pool (20 max conns) →
  `sqlx::migrate!` → build router → serve with `ConnectInfo` (needed by the per-IP rate limiter).
- Error model: `AppError` maps domain failures to `{ "error": ... }` JSON with correct statuses;
  internal errors are logged, never echoed.
- Audit catalog: `USER_REGISTERED`, `LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGIN_PASSKEY`, `LOGOUT`,
  `TWO_FACTOR_SETUP_STARTED`, `TWO_FACTOR_ENABLED`, `TWO_FACTOR_DISABLED`,
  `TWO_FACTOR_CHALLENGE_FAILED`, `VAULT_UPDATED`, `DEVICE_ADDED`, `DEVICE_REVOKED`,
  `PASSKEY_REGISTERED`, `PASSKEY_REVOKED`, `ADMIN_ROLE_CHANGED`, `ADMIN_SESSIONS_REVOKED`.
  Console *views* are deliberately not logged — only admin *actions* are.

## File storage

There is no file/blob storage: vault ciphertext lives in PostgreSQL (`vault_snapshots`), keyed by
version. Attachments/exports are not implemented.

## Real-time functionality

No WebSockets. "Real-time" sync is optimistic client state + debounced versioned uploads with
conflict reload; the admin console polls aggregates on page load.

## Performance

- Release profile: LTO, `codegen-units = 1`, stripped binaries (`Cargo.toml`).
- Hot paths are indexed: sessions by token hash, snapshots by `(user_id, version DESC)`, audit
  events by `created_at DESC` / `event_type`.
- Client crypto is WebCrypto-native (PBKDF2 310k iterations ≈ a fraction of a second per unlock).

## Troubleshooting

- **Port already in use** — the dev launcher skips components that answer health checks; kill
  strays with `taskkill /IM secure-vault.exe /F` (Windows) or stop the Postgres container:
  `docker stop secure-vault-postgres-5433`.
- **Web can't reach the API** — the rewrite targets `localhost:3001`; if you changed `PORT`, update
  `apps/web/next.config.js`.
- **`PUT /vault` returns 409** — a newer snapshot exists (another device). The client normally
  reloads automatically; a manual lock/unlock forces a resync.
- **Seeding fails with 409** — the demo account already exists; there is no admin delete API yet,
  so clear the dev DB (`docker exec secure-vault-postgres-5433 psql -U postgres -d secure_vault -c
  "DELETE FROM users WHERE email='demo@securevault.local'"`).
- **Docker Desktop not running** — `dev.mjs` tries to start it; if that fails, start it manually.

## Limitations

Honest inventory (each item verified against the code):

- `apps/desktop` (Tauri) and `apps/mobile` are **empty scaffolds**.
- `GET /api/v1/items` is a placeholder; item CRUD happens client-side on the encrypted vault.
- No email verification and no password-reset flow (for *either* password). Losing the account
  password without an existing session means losing the account; losing both the master password
  *and* the Secret Key loses the vault permanently — by design.
- Sessions are not bound to devices at login (`sessions.device_id` is used on device revoke, but
  new logins don't attach a device).
- Rate limiting is per-process in memory — the supported deployment is a **single API instance**
  (the production compose stack ships exactly that); a multi-instance deployment must move counters
  to shared storage first.
- The Redis container in `docker-compose.yml` is unused (it is the intended shared-store for the
  above).
- `SESSION_SECRET` is reserved but unused.
- `seed-demo.mjs --reset` cannot delete the existing demo account (no delete API) — manual SQL is
  required.
- `start-all.ps1` hardcodes machine-specific paths and a backend port that mismatches the web proxy.
- No external error monitoring (Sentry et al.) is wired in; structured logs + `/ready` polling are
  the current observability story.
- The deployment is designed for one host; scaling paths are described in ADR 0003.

## Roadmap

Natural next steps implied by the current state (none are implemented yet):

- Per-item trash / version-history UI over the existing `vault_snapshots` table.
- Email service integration (verification, reset links) via an isolated
  `integrations/` boundary + background job queue.
- Wire the desktop (Tauri) and mobile scaffolds; bind sessions to devices at login.
- Redis-backed rate limiting as the first step toward multi-instance deployments.
- External error monitoring (Sentry or equivalent) in the API + web containers.

## Contributing

There is no CONTRIBUTING file or issue template yet. Practical ground rules for this repo:
run `npm run lint` and `cargo fmt --check` before pushing; add tests for behavior change
(`crates/api/tests/api_flows.rs` for HTTP flows, `#[cfg(test)]` modules for units); keep the
zero-knowledge invariant — **no code may transmit key material or plaintext vault data**.

## License

The Rust workspace declares `license = "MIT"` (`secure-vault/Cargo.toml`), but **no LICENSE file
exists in the repository** — one should be added before publishing or accepting contributions.

## Credits

- Built on: axum, tokio, SQLx, tower-http, argon2, aes-gcm, RustCrypto crates, Next.js, React,
  Tailwind CSS, zustand, lucide-react.
- Breach checks: [Have I Been Pwned — Pwned Passwords](https://haveibeenpwned.com/) (k-anonymity
  range API) and [XposedOrNot](https://xposedornot.com/) (keyless email check). Neither service
  receives your master password, vault key, or vault contents.

## Documentation pointers

- [`secure-vault/docs/api.md`](secure-vault/docs/api.md) — full HTTP reference with examples
- [`secure-vault/docs/crypto.md`](secure-vault/docs/crypto.md) — cryptographic design details
- [`secure-vault/docs/threat-model.md`](secure-vault/docs/threat-model.md) — actors, mitigations, residual risks
- [`secure-vault/docs/architecture.md`](secure-vault/docs/architecture.md) — deeper architecture notes
- [`secure-vault/docs/deployment.md`](secure-vault/docs/deployment.md) — production deployment runbook
- [`secure-vault/docs/operations.md`](secure-vault/docs/operations.md) — operations: backups, restore, monitoring, lifecycle
- [`secure-vault/docs/security.md`](secure-vault/docs/security.md) — security inventory & residual risks
- [`secure-vault/docs/adr/`](secure-vault/docs/adr/) — architecture decision records
- [`secure-vault/README.md`](secure-vault/README.md) — the inner project README (deep backend/frontend walkthrough)

---

## Documentation Notes

Assumptions and caveats from generating this README against the actual code:

- **Verified by reading source:** all endpoints listed above exist in `crates/api/src/lib.rs`;
  the key ceremony in `apps/web/lib/crypto.ts` / `vaultKeys.ts` / `vaultEnvelope.ts` matches the
  seeder's ceremony in `scripts/seed-demo.mjs`; migrations 001–005 were read in full; audit event
  names were extracted from the route handlers; the 30 s clipboard clear, auto-lock, breach APIs,
  and sync/conflict behavior were confirmed in the client code; the integration tests confirm the
  register/2FA/vault/admin flows end-to-end.
- **Stale docs corrected here:** the inner `secure-vault/README.md` still describes the WebAuthn
  crate as a "stub", claims migrations end at 002, lists `docs/` as only two files, and omits the
  `/monitor` route and Secret-Key recovery — the code says otherwise. This README reflects the
  code; consider refreshing the inner README and `docs/architecture.md` next.
- **Unverified / not confirmed from the repo:** production deployment (no platform config beyond
  `docs/deployment.md`), real-world browser passkey behavior on specific authenticators (covered
  by synthetic-credential ceremony tests only), and exact lock-timeout option labels (the store
  exposes `lockTimeout`; option values were taken from the prior docs).
- **Nothing here should claim more than the code does:** placeholders are labeled placeholders,
  and "by design" limitations (irrecoverable vault, reversible TOTP secret) are documented as such.
- **Update this README when:** routes change (`crates/api/src/lib.rs`), migrations are added
  (`secure-vault/migrations/`), the key ceremony changes (`apps/web/lib/crypto.ts`), or the dev
  launcher's ports/flags change (`secure-vault/scripts/dev.mjs`).
