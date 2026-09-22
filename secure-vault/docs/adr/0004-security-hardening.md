# ADR 0004 — Production hardening decisions

- Status: accepted
- Date: 2026-09

## Context

Before this ADR the app was a faithful prototype: real crypto and auth, but
several behaviors that are unacceptable on a public deployment (first
registered user silently becomes admin; cookies without `Secure`; no TOTP
challenge throttling; unbounded snapshot/session growth; no account deletion
despite a UI button; `ip_hash` column never populated). Each decision below
closes one of those gaps.

## Decisions

1. **Secure cookies forced in production.** `APP_ENV=production` always sets
   the `Secure` cookie attribute (an explicit `COOKIE_SECURE=false` is
   overridden and warned about). Local HTTP dev stays insecure on purpose.
2. **First-user-admin bootstrap disabled in production.** Dev convenience
   kept for development only; production deployments promote admins via SQL
   or `ADMIN_EMAILS`. Rationale: a public site with the bootstrap hands the
   admin console to whoever registers first.
3. **TOTP challenge rate-limited.** A half-session (password accepted) could
   otherwise brute-force the ~10⁶ 6-digit code space; it now shares the
   10/min login limiter.
4. **Timing-equalized login.** Unknown emails burn a real Argon2id
   verification against a per-boot dummy hash; enumeration via response
   timing is no longer possible.
5. **Audit IP hashing.** `audit_events.ip_hash` stores salted SHA-256 of the
   client IP (`AUDIT_IP_SALT`); raw IPs are never stored. Stable salt gives
   correlatable, PII-free forensic value.
6. **Account deletion with audit preservation.** Self deletion requires the
   account password; both self and admin deletions run in one transaction
   that re-points the victim's audit events to a tombstone account
   (`00000000-…-0000`) so the trail survives the `ON DELETE CASCADE`.
7. **Data lifecycle enforcement.** Hourly maintenance deletes expired
   sessions (revoked ones after a 7-day grace) and prunes vault snapshots to
   `SNAPSHOT_RETENTION_COUNT` per user (newest never pruned).
8. **Request size cap.** 2 MiB `RequestBodyLimitLayer` on the whole router —
   the largest legitimate payload is a vault snapshot PUT.

## Alternatives considered

- **Signed, stateless sessions (JWT-style)** to make `SESSION_SECRET`
  meaningful. Rejected: server-side sessions are what make instant,
  per-user revocation ("revoke everywhere", admin force-logout) reliable.
- **Store raw IPs** for better abuse tooling. Rejected: PII minimization is
  cheap here and the salted hash preserves the correlation use case.
- **Soft-delete users** (deleted_at column). Rejected for a password
  manager: deletion is a compliance/rights feature — the encrypted data
  should actually disappear. Audit metadata is preserved instead.

## Consequences

- Migration 006 (tombstone role) and 007 (retention index) are additive.
- Multi-instance deployments remain unsupported until rate limiting moves to
  shared storage — documented as the primary known limitation.
