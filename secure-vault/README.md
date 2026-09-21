# SecureVault

A **zero-knowledge password manager** built with Rust (Axum + SQLx) and Next.js (React/TypeScript).

**The core promise:** the server authenticates you and stores your *encrypted* vault, but it never
possesses the keys required to read your passwords. If the database or the server itself is
compromised, an attacker gets ciphertext — nothing they can use without your master password.

---

## Table of Contents

1. [Why this project exists](#why-this-project-exists)
2. [Feature overview](#feature-overview)
3. [High-level architecture](#high-level-architecture)
4. [Cryptographic design](#cryptographic-design)
5. [Trust boundaries & what the server sees](#trust-boundaries--what-the-server-sees)
6. [Repository layout](#repository-layout)
7. [Database model](#database-model)
8. [Backend deep dive](#backend-deep-dive)
9. [Frontend deep dive](#frontend-deep-dive)
10. [End-to-end data flows](#end-to-end-data-flows)
11. [Admin console](#admin-console)
12. [Running locally](#running-locally)
13. [Configuration & environment](#configuration--environment)
14. [Testing](#testing)
15. [Security principles](#security-principles)
16. [Known limitations & roadmap](#known-limitations--roadmap)
17. [FAQ](#faq)
18. [Documentation pointers](#documentation-pointers)

---

## Why this project exists

Most password managers that "sync to the cloud" have a fundamental design weakness: the service
*can* decrypt your vault — by design or by legal/engineering accident — and a database breach leaks
your passwords in plaintext.

SecureVault is a demonstration of the opposite architecture, sometimes called **zero-knowledge /
end-to-end encryption**:

- Your **master password** never leaves your device.
- It is turned into a cryptographic key **locally**.
- Vault data is encrypted **before** it is transmitted, so the server stores ciphertext only.
- Losing the master password means the vault is unrecoverable — even by the operator, on purpose.

The project also explores the operational side that such systems still need: session management,
device tracking, **audit logging** ("who did what, when"), and a server-side **admin console** that
can observe and control *metadata and activity* — accounts, sessions, sync history, role changes —
without ever being able to read vault *contents*.

It is built as a monorepo with a Rust workspace (the backend) and a Next.js app (the UI), with
PostgreSQL for storage and Docker for local infrastructure.

---

## Feature overview

| Area | What it does |
|---|---|
| Encrypted vault | Vault documents are versioned, encrypted blobs. The Rust `vault` crate implements encrypt/decrypt with AES-256-GCM + a derived key (unit-tested). |
| Master password handling | Argon2id key derivation (server-side crypto crate); the Web UI keeps the key purely client-side (Web Crypto). See [Cryptographic design](#cryptographic-design) for the exact current split. |
| Accounts & sessions | Email + account password (Argon2id-hashed), 24 h server sessions, HttpOnly cookies, revocable sessions. |
| Devices | Register/revoke devices; revoking a device also revokes its sessions. |
| Roles | `user` / `admin` on every account; role is read from the DB on every request. |
| Admin console | `/admin` in the UI — Overview stats, User/access management, full Audit Log. |
| Audit log | Every meaningful action is recorded (`LOGIN_*`, `LOGOUT`, `VAULT_UPDATED`, device events, admin actions) with optional JSON metadata. |
| Sync history | Every accepted vault upload is persisted as a `vault_snapshots` row (version + size + ciphertext), so sync activity is observable. |
| Password generator | Client-side, `crypto.getRandomValues`, length 8–64, charset toggles, strength meter. |
| Security center | Local analysis of vault items: weak / reused / missing passwords, overall score /100. Nothing is sent to the server. |
| Auto-lock | Vault locks after inactivity (configurable 1/5/15/30 min or never); keys are dropped from memory on lock. |
| Clipboard hygiene | Copied passwords are cleared from the clipboard after 30 seconds. |
| Passkeys (WebAuthn) | Register a platform passkey (Touch ID / Windows Hello / security key) as a second factor, then sign in with it alone — no password. Full server-side verification: CBOR attestation parsing, COSE key handling (ES256 + RS256), challenge/origin/RP-ID binding, UV enforcement, signature-counter replay protection. Ceremony-tested against synthetic P-256 credentials. |

---

## High-level architecture

```
                        YOUR BROWSER
                              │
              ┌───────────────▼────────────────┐
              │ Next.js app (apps/web)         │
              │  · vault lock state            │
              │  · local key material          │
              │  · encryption (client side)    │
              └───────────────┬────────────────┘
                              │  /api/*  (rewritten by next.config.js)
              ┌───────────────▼────────────────┐
              │ Axum API (crates/api, :3001)   │
              │  auth · sessions · roles       │
              │  vault/snapshot endpoints      │
              │  devices · audit · admin       │
              └───────────────┬────────────────┘
                              │  SQLx
              ┌───────────────▼────────────────┐
              │ PostgreSQL 16 (Docker)          │
              │  migrations/001..005            │
              └────────────────────────────────┘
```

Rust crates (each with a single responsibility):

| Crate | Responsibility |
|---|---|
| `crates/api` | HTTP server: routes, auth extractor, admin console, error mapping, router wiring, migrations runner |
| `crates/auth` | Session logic: create / validate / revoke sessions, password `authenticate` (also unit-tested) |
| `crates/crypto` | All cryptography: Argon2id KDF, AES-256-GCM, HKDF, TOTP (RFC 6238), hashing, password generator, key-wrap helpers |
| `crates/vault` | `VaultEngine`: serialize → encrypt / decrypt → deserialize vault documents, vault-key re-wrap (unit-tested) |
| `crates/models` | Shared serde structs: `User`, `Vault`, `Device`, `Session`, `AuditEvent`, `VaultData`, `VaultItem`, … |
| `crates/audit` | Audit-log insertion (`log_event`, `log_event_with_meta`) |
| `crates/database` | Shared DB connection utilities (lifecycle/migrations live in the API binary) |
| `crates/config` | Environment-based configuration (`AppConfig`) |
| `crates/webauthn` | Stub service for passkey registration/authentication options (not wired to endpoints yet) |

---

## Cryptographic design

### Key hierarchy

```
MASTER PASSWORD  (entered locally, never transmitted)
     │
     ▼  Argon2id (memory-hard KDF)
Key Encryption Key (KEK)
     │
     ▼  AES-256-GCM   ("wrap" the vault key)
Vault Encryption Key (VEK)   ← random 32 bytes, per vault
     │
     ▼  AES-256-GCM   AAD = "secure-vault-v1"
Encrypted Vault (versioned JSON document of items/folders)
```

Why the two-layer design:

- Changing the master password only re-encrypts the *VEK* — the whole vault never needs
  re-encryption (see `VaultEngine::re_encrypt_vault_key`).
- The VEK is random and long, so the vault blob can use a fast authenticated cipher safely.
- The KEK is derived with Argon2id so offline guessing of a weak master password is expensive.

### Algorithms used (Rust `crates/crypto`)

| Purpose | Algorithm | Where |
|---|---|---|
| Account password hashing | Argon2id (default params) | `hash_password` / `verify_password` |
| Master-password → KEK | Argon2id, memory 65536 KiB, iterations 3, parallelism 2 | `derive_key_from_password` |
| Sub-key derivation | HKDF-SHA256 (info: `secure-vault-key-derivation`) | `derive_subkey` |
| Vault / key-wrap encryption | AES-256-GCM, 12-byte random nonce, optional AAD | `encrypt` / `decrypt` |
| Session token hashing | SHA-256 (token is high-entropy random, so SHA-256 is appropriate) | `hash_sha256` |
| Randomness | `rand`/`aes-gcm` `OsRng` — never `Math.random` on the server | everywhere |
| Password generation | `OsRng` over a chosen charset | `generate_password` |

**Web client (`apps/web/lib/crypto.ts`)** uses the Web Crypto API (`crypto.subtle`):

- `deriveKeyFromPassword` — PBKDF2 (SHA-256) → AES-GCM key (this is the *WebCrypto-compatible*
  path; browsers have no native Argon2id),
- `encryptData` / `decryptData` — AES-256-GCM with a random 12-byte IV,
- `generatePassword` — `crypto.getRandomValues`, uniform charset sampling,
- `calculateEntropy` / `getPasswordStrength` — entropy-based scoring used by the Security Center,
  detail pages and the generator.

> **Current-status note (important):** the *server-side* crypto engine (`crypto` + `vault` crates)
> implements the full Argon2id + AES-GCM hierarchy above and is unit-tested. The *Web UI*'s vault
> flow is currently a local demo: `unlock` populates an empty vault in memory (`unlock([], [])`)
> and items live in a Zustand store, encrypted never leaves the client. Registering does call the
> API, which stores KDF parameters + an encrypted (placeholder) vault key on the server. The
> full client-side "download blob → decrypt with master password → edit → upload new version" loop
> is the main remaining integration — see [Known limitations & roadmap](#known-limitations--roadmap).

---

## Trust boundaries & what the server sees

**What the server CAN see**

- Account email + role (`user` / `admin`)
- Argon2id password hash for the *account password* (used for login; distinct from the vault master
  password)
- Encrypted vault snapshots (version + size + ciphertext — **never decrypted**)
- KDF parameters and the *encrypted* vault key
- Passkey public keys (schema)
- Session/device metadata
- Audit events (logins, syncs, device changes, admin actions)

**What the server NEVER receives**

- ❌ The master password (only the *encrypted* vault key is uploaded at registration)
- ❌ The vault encryption key (VEK)
- ❌ Plaintext passwords, notes, URLs inside the vault
- ❌ Recovery secrets

**Threat model** (full document: `docs/threat-model.md`): actors are the user, a DB leaker, a
backend admin, a network attacker, and an offline attacker. Protected against: DB leaks
(ciphertext only), backend-admin reads (zero-knowledge), stolen sessions (hashed tokens, short
expiry, revocation), interception (TLS in production), tampering (AES-GCM auth tag), and password
guessing (Argon2id). Documented residual risks are malware/keyloggers on an unlocked device — **no
web app can make a compromised device trustworthy**, and SecureVault doesn't claim to.

---

## Repository layout

```
secure-vault/
├── apps/web/                  Next.js frontend (TypeScript + Tailwind)
│   ├── app/                   Route pages (App Router)
│   │   ├── page.tsx           Marketing/landing page
│   │   ├── login|register|unlock
│   │   ├── dashboard|vault|vault/new|vault/[id]|generator|security|devices|settings
│   │   └── admin/             Admin console: overview | users | audit
│   ├── components/            Sidebar, VaultItemCard, PasswordGenerator, admin/*
│   ├── hooks/                 useVault (Zustand store), useAuth, useAutoLock
│   ├── lib/                   api.ts (typed API client), crypto.ts (WebCrypto helpers)
│   └── styles/globals.css     Design tokens + reusable component classes
├── crates/
│   ├── api/                   Axum server, routes, auth extractor, error mapping
│   ├── auth/                  Session create/validate/revoke, authenticate
│   ├── crypto/                KDF, AES-GCM, HKDF, hashing, generators
│   ├── vault/                 VaultEngine encrypt/decrypt/re-wrap
│   ├── database/              Pool helpers
│   ├── models/                Shared serde models
│   ├── webauthn/              Passkey stub service
│   ├── audit/                 Audit log writes
│   └── config/                AppConfig from env
├── migrations/
│   ├── 001_initial_schema.sql   users, vaults, devices, passkeys, sessions, audit_events
│   └── 002_admin_and_snapshots.sql  roles, vault_snapshots, audit indexes
├── docs/                      api.md (HTTP reference), threat-model.md
├── tests/                     Empty scaffolding: crypto/, integration/, security/
├── docker-compose.yml         PostgreSQL 16 (+ Redis, unused so far)
├── start-all.ps1              One-command Windows launcher
├── Cargo.toml                 Workspace manifest (shared dependency versions)
└── .env.example               Environment template
```

---

## Database model

Applied automatically at API startup (`sqlx::migrate!`). All FKs cascade deletes to children.

| Table | Purpose | Notable columns |
|---|---|---|
| `users` | Accounts | `email` (unique), `password_hash`, `role` (`user`/`admin`, CHECK-constrained) |
| `vaults` | One per user | KDF params (`Argon2id` memory/iterations/parallelism), `kdf_salt`, `encrypted_vault_key`, `version` |
| `vault_snapshots` | Sync history (v2) | `version`, `blob_size`, `ciphertext`, per `user_id`, indexed by `(user_id, version DESC)` |
| `devices` | User devices | `name`, `device_type`, `public_key`, `last_seen_at`, `revoked_at` |
| `passkeys` | WebAuthn credentials (planned) | `credential_id` (unique), `public_key`, `sign_count`, `revoked_at` |
| `sessions` | Login sessions | `token_hash` (SHA-256, unique), `device_id`, `expires_at`, `revoked_at` |
| `audit_events` | Append-only-ish event log | `event_type`, `device_id`, `metadata` (JSONB), `created_at` (indexed), `user_id` |

Conventions: UUID primary keys (`uuid_generate_v4()`), `created_at/updated_at TIMESTAMPTZ DEFAULT
now()`, audit indexes on `created_at DESC` and `event_type` for the admin feed.

---

## Backend deep dive

### Boot sequence (`crates/api/src/main.rs`)

1. Read `AppConfig` from environment (`secure_vault_config::AppConfig::from_env`).
2. Open a `PgPool` (20 max connections).
3. Run migrations from `../../migrations`.
4. Build the router: public routes (health, ready, register, login) + everything else.
5. Bind and serve.

### Authentication

- **Register** (`POST /auth/register`): validates input, rejects duplicate emails, hashes the
  *account* password with Argon2id, inserts the user (assigning role — see below), creates an empty
  vault row with a random salt and an encrypted placeholder vault key derived from the
  `master_password`, and logs `USER_REGISTERED`.
- **Login** (`POST /auth/login`): verifies the account password, checks `ADMIN_EMAILS` for possible
  elevation, creates a session (64-char random token; **only its SHA-256 hash is stored**), sets an
  `HttpOnly; SameSite=Lax; Path=/` cookie (24 h), logs `LOGIN_SUCCESS` (or `LOGIN_FAILED`).
- **Every protected request** takes an `AuthenticatedUser` extractor
  (`crates/api/src/middleware/auth.rs`). It reads the `session_token` cookie, hashes it, joins
  `sessions` → `users`, and checks expiry/revocation — and returns the **role fresh from the DB on
  every request**, so demotions and session revocations apply instantly. (This is an extractor, not
  a middleware layer; earlier versions of this codebase that layered middleware never compiled on
  the pinned axum.)
- **Logout** revokes all of the user's sessions and clears the cookie.
- **`GET /auth/me`** returns `{ user_id, email, role, totp_enabled }` — the UI uses it to show/hide
  the Admin console, gate pages, and reflect 2FA status.
- **Passkeys** (`/auth/passkeys/*`): a second, passwordless way in.
  - `POST /auth/passkeys/register/options` → `PublicKeyCredentialCreationOptions` + a
    single-use `ceremony_id` (challenges live in-memory, 5 min TTL, bound to the session's email).
  - `POST /auth/passkeys/register/finish` verifies the attestation (challenge, origin,
    RP-ID hash, UP flag; `none` and `packed` self-attestation formats) and stores the
    credential's COSE public key + signature counter in `passkeys`.
  - `POST /auth/passkeys/login/options` (empty body = usernameless/discoverable) and
    `.../login/finish` verify the assertion — signatures cover
    `authData || SHA-256(clientDataJSON)` per §6.5.6, user verification is **required**
    (a passkey is the only factor in that flow), and the counter must move forward.
    A verified assertion mints a **full session** and logs `LOGIN_PASSKEY`.
  - `GET /auth/passkeys` and `DELETE /auth/passkeys/:id` manage registered credentials.
  - Rate limiting is shared with password login; a passkey proves the account, but the
    vault itself still needs the master password or Secret Key client-side.

### Roles & the admin console

`users.role` is `user` by default. Bootstrap rules:

- If `ADMIN_EMAILS` is set, any account whose email is listed is granted `admin` at register *and*
  re-checked at every login (so adding an email later promotes an existing account on next sign-in).
- If `ADMIN_EMAILS` is empty, the **first registered account** becomes admin (development
  convenience).

Admin routes are inside the normal authenticated tree; every handler starts with
`ensure_admin(&auth_user)?` (403 otherwise). Full details in the [Admin console](#admin-console)
section.

### HTTP API surface (base `/api/v1`)

| Method & path | Auth | Description |
|---|---|---|
| `GET /health`, `GET /ready` | — | Liveness / readiness |
| `POST /auth/register` | — | Create account + vault |
| `POST /auth/login` | — | Create session, set cookie |
| `POST /auth/logout` | ✅ | Revoke all sessions |
| `GET /auth/refresh`, `GET /auth/me` | ✅ | Session validation / identity + role |
| `GET /vault` | ✅ | Encrypted vault material (KDF params, encrypted key) |
| `PUT /vault` | ✅ | Upload new version `{version, ciphertext, nonce}` (base64). Rejects stale versions (conflict); persists a `vault_snapshots` row; logs `VAULT_UPDATED` with version + blob size |
| `GET /devices` / `POST /devices` | ✅ | List / register devices |
| `DELETE /devices/:device_id` | ✅ | Revoke device + its sessions |
| `GET /items` | ✅ | Placeholder (item ops are client-side on the encrypted vault) |
| `GET /admin/overview` | admin | Totals + 15 most recent audit events |
| `GET /admin/users` | admin | All accounts with joined activity counts |
| `PATCH /admin/users/:user_id/role` | admin | Promote/demote (guards: no self-change, no demoting the last admin) |
| `POST /admin/users/:user_id/revoke-sessions` | admin | Force sign-out everywhere |
| `GET /admin/audit` | admin | Paginated, filterable audit feed (`limit`≤200, `offset`, `event_type`, `user_id`) |

Path-parameter syntax is **`/users/:user_id`** — axum 0.7/matchit 0.7 syntax (not the `{id}` form
from axum 0.8; earlier versions of this codebase used `{id}` and every parameterized route 404'd).

### Audit event catalog

| Event | When | Metadata |
|---|---|---|
| `USER_REGISTERED` | New account | `{role}` |
| `LOGIN_SUCCESS` / `LOGIN_FAILED` | Login attempt | — |
| `LOGIN_PASSKEY` | Successful passkey-only sign-in | — |
| `LOGOUT` | Logout | — |
| `PASSKEY_REGISTERED` / `PASSKEY_REVOKED` | Passkey lifecycle | — |
| `TWO_FACTOR_SETUP_STARTED` / `TWO_FACTOR_ENABLED` / `TWO_FACTOR_DISABLED` / `TWO_FACTOR_CHALLENGE_FAILED` | TOTP lifecycle | `{target_user}` where relevant |
| `VAULT_UPDATED` | Accepted vault upload | `{version, blob_bytes}` |
| `DEVICE_ADDED` / `DEVICE_REVOKED` | Device lifecycle | — |
| `ADMIN_ROLE_CHANGED` | Role change by an admin | `{target_user, target_user_id, previous_role, new_role}` |
| `ADMIN_SESSIONS_REVOKED` | Session purge by an admin | `{target_user, target_user_id, revoked_count}` |

(Console *views* are deliberately **not** logged — logging reads would pollute the feed with an
`ADMIN_*_VIEWED` row on every page open. Only admin *actions* are recorded.)

Events carry the *actor's* `user_id` (the event row's `user_id` FK); metadata records the target.

### Error model

`AppError` (`crates/api/src/errors.rs`) maps to JSON `{ "error": "..." }` responses:
401 Unauthorized, 403 Forbidden, 404 NotFound, 400 Validation/Vault, 409 Conflict, 429 RateLimited,
500 internal (logged, not echoed).

---

## Frontend deep dive

### Routing map (Next.js App Router)

| Route | Purpose |
|---|---|
| `/` | Marketing/landing page ("Create Vault" / "Sign In") |
| `/register` | Create account (email, account password, master password ≥ 12 chars) |
| `/login` | Sign in |
| `/unlock` | "Vault locked" gate — enters the vault (currently local demo: unlocks an empty in-memory vault) |
| `/dashboard` | Security overview; redirects to unlock when locked |
| `/vault` (+ `/vault/new`, `/vault/[id]`) | Item grid, search, add account, detail view (reveal/copy/strength/delete) |
| `/generator` | Password generator with strength meter |
| `/security` | Local security score, weak/reused/missing analysis, recommendations |
| `/devices` | Registered devices, revoke |
| `/settings` | Auto-lock timeout, clipboard security, data (export/import/delete are UI placeholders) |
| `/admin`, `/admin/users`, `/admin/audit` | Admin console (role-gated) |

### State & behavior

- `hooks/useVault.ts` (Zustand): `isLocked`, `items[]`, `folders[]`, search query, selected item,
  lock timeout + last activity. `lock()` wipes items/keys from memory; `unlock()` seeds the vault.
  Item CRUD (`addItem/updateItem/removeItem`) is client-side.
- `hooks/useAutoLock.ts`: listens for activity events (mouse/key/scroll/touch), checks every 10 s
  whether the idle time exceeded the configured timeout, then `lock()`s.
- `hooks/useAuth.ts` (Zustand): holds the current `{user_id, email, role}` from `/auth/me`;
  `refresh()` is called by the `Sidebar` on every route change, so the role-driven **Admin**
  sidebar entry appears/disappears as soon as the session is known. (Logging in is what flips it on
  — no page reload needed.)
- `components/Sidebar.tsx`: nav list (`Dashboard … Settings`), plus an `Admin` item — inserted
  before Settings — only when `role === 'admin'`. Shows vault lock state + "Lock Vault" action.
- `components/admin/AdminShell.tsx`: shared role gate + tab bar for the three admin pages;
  non-admins get an explanatory "Admin access required" card, anonymous visitors get
  "Sign in required". The pages themselves only fetch data once `me.role === 'admin'`.

### API client (`lib/api.ts`)

Single `request<T>()` wrapper: JSON in/out, `credentials: 'include'`, throws the server's `error`
message on non-2xx. Typed groups: `auth`, `vault`, `devices`, `admin`, `health`. The browser talks
to `/api/*`, which `next.config.js` rewrites to `http://localhost:3001/api/*`.

### Styling

Dark-first design tokens (`hsl` CSS variables: `--background`, `--card`, `--primary`, `--muted`,
`--border`, …) defined in `styles/globals.css` with reusable classes — `.card`, `.input`, `.label`,
`.btn-primary`, `.btn-ghost`, `.btn-danger`, `.alert-error` — composed with Tailwind utilities.
`cn(...)` in `lib/crypto.ts` joins class strings.

### Clipboard & UX details

Copy actions write to the clipboard and **clear it after 30 seconds** (username, password,
generated passwords); detail pages reveal passwords with an eye toggle and show a live strength
bar; the generator avoids SSR/CSR password mismatches by generating in `useEffect`.

---

## End-to-end data flows

**New user:**
`/register` → `POST /auth/register` → account + Argon2id hash + vault row (salt, encrypted VEK)
→ `USER_REGISTERED` event → user signs in.

**Sign-in:**
`POST /auth/login` → session created (hash stored) → `Set-Cookie: session_token` (HttpOnly, 24 h)
→ `LOGIN_SUCCESS` → client calls `GET /auth/me` → sidebar learns the role → (if admin) Admin
console appears.

**Vault sync (server side):**
`PUT /vault {version, ciphertext, nonce}` → rejected if `version <= current` (conflict
protection) → `vaults.version` bumped → ciphertext persisted to `vault_snapshots` (size recorded)
→ `VAULT_UPDATED {version, blob_bytes}` audit event. The admin console aggregates these into
"vault syncs" totals and per-user sync counts.

**Admin auditing an action:**
Admin opens `/admin/users` (views aren't audit-logged) → demotes `alice@example.com` →
`PATCH /admin/users/:id/role` → guards pass → role updated → `ADMIN_ROLE_CHANGED` event carries
`{target_user, previous_role, new_role}` → next request from `alice` reads the new role (403 on
admin routes if demoted). Revoking her sessions makes her next API call 401 immediately.

**Admin visibility boundary:** the console sees *what changed and who did it*, plus sync
metadata — never decrypted items.

---

## Admin console

The server has a role-based admin console (`/admin` in the web app) for observing data flow and
controlling access. It is **not** a way to read vault contents — SecureVault is zero-knowledge, so
admins see accounts, sessions, devices, sync activity, and the full audit trail instead.

- **Overview** — totals (users, admins, active sessions/devices, vault syncs, events 24h/total,
  signups 24h) and the 15 most recent audit events, with color-coded event chips.
- **Users & Access** — every account with created/last-active times, device/session/sync counts;
  per-user actions: **Make admin / Demote** and **Revoke sessions**. You cannot change your own
  role; the last admin cannot be demoted. Role changes and revocations are themselves audit-logged
  with actor + target. Accounts are never hard-deleted from the console (deletion would cascade
  away their audit history).
- **Audit Log** — paginated (50/page) feed over all event types, filterable by event type.

Roles: `users.role` is `user` (default) or `admin`, read fresh from the DB on every authenticated
request. Bootstrap: `ADMIN_EMAILS` env (comma-separated) grants admin at register/login; if unset,
the first registered account becomes admin (dev convenience). Promote an existing account with:

```sql
UPDATE users SET role = 'admin' WHERE email = 'you@example.com';
```

All `/api/v1/admin/*` endpoints require the `admin` role (403 otherwise); non-admin users are
warned in the UI and given instructions (`ADMIN_EMAILS` or ask another admin).

---

## Running locally

```bash
# 1. Start the database
docker compose up -d

# 2. Run the backend (listens on :3001 by default)
#    create secure-vault/.env from .env.example first
cargo run -p secure-vault-api

# 3. Run the frontend (pinned to :3000)
cd apps/web
npm install
npm run dev
```

Then open http://localhost:3000 (UI) / http://localhost:3001/health (API).

- The `dev` script pins `next dev -p 3000` so a stray `PORT` cannot silently rebind the UI.
- The frontend proxies `/api/*` → `http://localhost:3001/api/*` via `next.config.js`. If you move
  the API to another port, update the rewrite (and any `PORT`/`.env` value).
- **`start-all.ps1`** (Windows) starts Docker + backend + frontend in one script. Note its
  defaults: it builds into a separate cargo target dir and defaults the backend to port **8080** —
  if you use it, pass `-BackendPort 3001` (or update `next.config.js`) so the proxy lines up.
  The user's working Rust toolchain is a full WinLibs/mingw64 on `PATH` (the sandbox shell needs a
  libgcc stub workaround; a normal WinLibs environment does not).

---

## Configuration & environment

`AppConfig` (see `crates/config/src/lib.rs` and `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgres://postgres:postgres@localhost:5432/secure_vault` | SQLx pool |
| `SESSION_SECRET` | `change-me-in-production` | Reserved (cookie/session signing) |
| `PORT` | `3001` | API bind port |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated allowed origins |
| `WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGIN` | `localhost` / `http://localhost:3000` | Future passkey RP config |
| `ADMIN_EMAILS` | *(empty)* | Comma-separated emails granted admin. Empty ⇒ first registered account becomes admin |
| `APP_ENV` | `development` | Environment marker |

`docker-compose.yml` runs `postgres:16-alpine` (db `secure_vault`, user/password `postgres`) and a
Redis container that the app does not use yet.

---

## Testing

```bash
# Backend unit tests
cargo test

# Frontend
cd apps/web
npm run lint
npm run build   # also validates every route compiles (includes the admin pages)
```

Currently meaningful unit tests live in `crates/crypto` (encrypt/decrypt roundtrip, wrong-key and
tamper detection, password hash/verify, KDF determinism, generator length),
`crates/auth` (token uniqueness, deterministic token hashing) and `crates/vault`
(vault encrypt→decrypt roundtrip with a realistic item). `tests/{crypto,integration,security}/`
are empty scaffolds for future integration/security suites. The API was also verified end-to-end
against a real Postgres (register/login with roles, 403 gating, promote/demote guards, session
revocation → immediate 401, snapshot persistence + `VAULT_UPDATED` metadata, audit filtering).
Full HTTP reference: `docs/api.md`.

---

## Security principles

1. **Never use `Math.random()`** for cryptographic randomness — `crypto.getRandomValues` (client),
   `OsRng` (server).
2. **Never log secrets.** All secrets have redacted representations.
3. **Never send plaintext vault data to the server** — encrypted client-side first.
4. **Authenticated encryption** (AES-256-GCM) detects ciphertext tampering.
5. **Memory-hard KDF** (Argon2id) resists offline password guessing.
6. **Auto-lock** drops decryption keys from active memory.
7. **Session tokens are stored hashed**, expire in 24 h, and can be revoked (individually or all).
8. **Roles are checked server-side on every request** (fresh DB read) and admin actions are
   themselves audit-logged.
9. **Do not invent cryptographic algorithms** — use established libraries and protocols.
10. **TOTP two-factor** (RFC 6238) gates login: half-sessions can only answer the challenge, and
   disabling 2FA requires both a current code and the account password.
11. **Auth endpoints are rate-limited** (in-memory sliding window) and CORS origins are pinned via
   `CORS_ORIGINS` rather than permissive-by-default.

---

## Known limitations & roadmap

Honest inventory of where this project stands:

- **Client vault sync is live.** The browser derives the KEK with WebCrypto PBKDF2 (WebCrypto has
  no native Argon2id), wraps a random VEK, and `useVaultSync` pushes/pulls encrypted snapshots to
  `PUT/GET /vault` with version-conflict resolution; legacy vaults upgrade to the random-key
  hierarchy on their next master-password change. A per-item trash / version-history view over the
  existing `vault_snapshots` table is the natural next milestone.
- **Passkeys/WebAuthn** are schema + stub service only.
- **`audit_events.ip_hash`** is not populated yet (needs client IP capture).
- **No email verification / password reset** (deliberate for vault recovery, but account-password
  reset flows don't exist either).
- Sessions are not yet bound to a device at login (`device_id` is in the schema and the
  `devices` flows use it on revoke).
- Cookies are not `Secure` in dev (HTTP localhost) — add `Secure` + domain handling for HTTPS
  production.
- Export/import/delete buttons in Settings are UI placeholders.
- Recovery: losing the master password loses the vault **by design** — the server cannot help.

---

## FAQ

**Can the operator read my passwords?** No — only encrypted material is stored; the vault key
never leaves the client (see trust-boundary table above).

**What happens if the database leaks?** An attacker obtains Argon2id hashes, session-token hashes,
and AES-256-GCM ciphertext — no usable passwords, and offline guessing is throttled by Argon2id
cost.

**Why is there an "account password" *and* a "master password"?** The account password
authenticates to the service (server-verifiable hash). The master password is the key to the vault
and is never sent. (Current UI asks for both at registration.)

**Why PBKDF2 in the browser but Argon2id in Rust?** Argon2id is the better KDF, but browsers only
expose PBKDF2/HKDF in WebCrypto; Argon2id in the browser requires a WASM dependency. The Rust
server-side engine uses Argon2id.

**How do I become an admin?** Set `ADMIN_EMAILS` and sign in, promote yourself from another admin
via `/admin/users`, or `UPDATE users SET role='admin' ...` (first registered account is admin by
default when `ADMIN_EMAILS` is empty).

**How long do sessions last?** 24 hours; revocable at any time (logout revokes all of yours; an
admin can revoke any user's).

---

## Documentation pointers

- `docs/api.md` — HTTP API reference with request/response examples.
- `docs/threat-model.md` — actors, mitigations, documented residual risks.
- `.env.example` — environment template with comments.
- `migrations/` — schema history (each file documents its intent).
