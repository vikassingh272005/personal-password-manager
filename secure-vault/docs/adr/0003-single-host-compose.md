# ADR 0003 — Single-host Docker Compose + Caddy for production

- Status: accepted
- Date: 2026-09

## Context

The project needs a real, publicly reachable deployment (HTTPS, persistent
DB, migrations, backups) while remaining a personal-scale product. The
deployment story should be boring, cheap, auditable, and portable.

## Decision

One Linux host, Docker Compose (`docker-compose.prod.yml`): Caddy (TLS) →
web (Next.js standalone) → api (Rust) → Postgres, with named volumes for DB
data and certs, `.env.prod` for secrets, `docker/backup-db.sh` +
`docker/restore-db.sh` for the backup/restore loop, and an SSH-based deploy
workflow (`.github/workflows/deploy.yml`).

## Alternatives considered

- **Managed PaaS (Fly.io / Railway / Render) + managed Postgres.** Good
  option when zero-ops matters more than cost/control; the API image is
  portable to them unchanged. Rejected for now: single-tenant personal scale,
  per-service cost, and the desire to keep backups/migrations visible in-repo.
- **Kubernetes.** Rejected outright at this scale (operational complexity
  with no benefit for one stateful service).
- **Serverless (e.g. Lambda).** Rejected: long-lived Postgres connections,
  in-memory rate limiters, and a 60 MB binary with embedded migrations all
  fight the model.

## Consequences

- Scaling path is explicit: first bottleneck is the single Postgres (move to
  managed PG — DATABASE_URL change only), then API horizontal scale (which
  requires moving rate limiting to shared storage, see security.md), then
  web is stateless and scales trivially.
- Trade-off: the operator owns backups and OS updates; the runbooks live in
  `docs/operations.md` because nothing external enforces them.
