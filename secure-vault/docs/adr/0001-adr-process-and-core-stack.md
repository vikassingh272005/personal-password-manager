# ADR 0001 — ADR process & core stack (Rust/axum, PostgreSQL, Next.js)

- Status: accepted (pre-existing decision, recorded here retroactively)
- Date: 2026-09

## Context

The project began as a zero-knowledge password manager with heavy client-side
crypto. The stack had to support a long-lived async HTTP API, compile-time
SQL checking, and a browser client doing all encryption.

## Decision

Rust 2021 + axum 0.7 + SQLx 0.8 + PostgreSQL 16 for the API; Next.js 14
(App Router) + WebCrypto for the web client; one repo, workspace-per-language.

## Alternatives considered

- **Node/TypeScript API (single language).** Rejected: no compile-time SQL
  verification, weaker story for Argon2/WebAuthn primitives, and the team
  wanted a hard separation between "crypto-adjacent" server code and UI code.
- **Go + sqlx-equivalent.** Rejected for the same verification reasons;
  axum's extractor model maps cleanly onto the auth rules.
- **MongoDB / SQLite.** Rejected: multi-user concurrent writes, JSONB audit
  metadata, transactions for snapshot inserts, and managed-PG availability.

## Consequences

- Migrations are SQL files applied by `sqlx::migrate!` at startup (no extra
  migration tooling to deploy).
- The web app proxies `/api/*` (same origin in production) which keeps the
  zero-knowledge cookie story simple (`SameSite=Lax`, first-party).
- Trade-off: two build toolchains to maintain (cargo + npm) in CI.
