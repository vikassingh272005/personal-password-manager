# Operations

Day-2 operations for a deployed SecureVault instance. Paths and service names
assume the production compose stack (`docker-compose.prod.yml`); adjust for
other hosts.

## Health & monitoring

| Check | Command / URL | Healthy when |
|---|---|---|
| Liveness | `curl -fsS https://domain/health` | `{"status":"ok"}` |
| Readiness | `curl -fsS https://domain/ready` | `{"status":"ready"}` (DB reachable) |
| Containers | `docker compose --env-file .env.prod -f docker-compose.prod.yml ps` | all `healthy`/`running` |

The compose `HEALTHCHECK`s use `/ready` (API) and a lightweight HTTP probe
(web), so `docker ps` reflects real health. For alerting, poll `/ready` from
an external monitor (UptimeRobot, Better Stack, Healthchecks.io) — it fails
when the database is unreachable, which is the outage that matters. API logs
are structured (`RUST_LOG=info`, request spans from tower-http include method,
path and latency).

What to watch: `/ready` failures, `500` spikes in API logs, and disk usage of
the `db_data` volume.

## Logs

```bash
docker compose --env-file .env.prod -f docker-compose.prod.yml logs -f api
docker compose --env-file .env.prod -f docker-compose.prod.yml logs -f web
```

Log hygiene: the API never logs passwords, tokens, ciphertext or key material.
Login/2FA/passkey audit events carry a **salted SHA-256 of the client IP** —
never the raw address (see `docs/security.md`). The application audit trail
lives in the `audit_events` table (admin console → Audit Log), which survives
account deletion via the tombstone re-point.

## Backups

The database is the only stateful service (TLS certs re-issue automatically;
the web/api containers are stateless).

```bash
# Ad-hoc
./docker/backup-db.sh /srv/backups

# Nightly (cron on the host)
15 4 * * *  cd /srv/securevault && ./docker/backup-db.sh /srv/backups >> /var/log/sv-backup.log 2>&1
```

`backup-db.sh` runs `pg_dump -Fc` inside the `db` container (consistent
snapshot, compressed), names files `secure_vault-YYYYmmdd-HHMMSS.dump`, and
prunes local dumps older than `BACKUP_RETENTION_DAYS` (default 14).

**The dump is sensitive even though vault items are zero-knowledge**: it
contains Argon2id password hashes, reversible TOTP secrets and vault
ciphertext. Copy dumps off-site over an encrypted channel (e.g.
`rclone copy` to object storage with SSE, or `scp` to another host) and
restrict permissions (`chmod 600`). Off-site copies are what makes the local
volume failure scenario survivable.

Restore procedure: `docker/restore-db.sh <dump>` (add `--force` to overwrite a
non-empty database; the script stops the API first and verifies intent).
**Test restores monthly** — an unverified backup is a hope, not a plan:

```bash
# on a scratch machine/host:
./docker/restore-db.sh ./backups/secure_vault-latest.dump --force
curl -fsS http://localhost/ready   # then log in with a real account
```

## Data lifecycle (what the server does automatically)

| Data | Created | Retained | Deleted |
|---|---|---|---|
| Vault snapshots | every sync (`PUT /vault`) | newest `SNAPSHOT_RETENTION_COUNT` per user (default 20) | hourly cleanup task prunes older ones; newest is never pruned |
| Sessions | login/register/passkey | 24 h expiry | cleanup deletes expired rows hourly; revoked rows after a 7-day forensic grace window |
| User & vault data | registration | until deleted | account deletion (self or admin) cascades everything in one transaction |
| Audit events | every sensitive action | indefinitely (small rows) | re-pointed to a tombstone account on user deletion — the trail outlives the user |

The cleanup task (`crates/api/src/maintenance.rs`) runs at boot and then
hourly; failures are logged and retried, never fatal. `SNAPSHOT_RETENTION_COUNT=0`
disables pruning (snapshots then need manual vacuuming decisions).

## Common procedures

**Promote an admin** (see deployment.md §First admin):
```bash
docker compose --env-file .env.prod -f docker-compose.prod.yml exec db \
  psql -U securevault -d secure_vault -c "UPDATE users SET role='admin' WHERE email='…';"
```
The change takes effect on the victim's very next request (roles are read
from the DB per request).

**Revoke a user's sessions** — admin console → Users → "Revoke sessions"
(audited as `ADMIN_SESSIONS_REVOKED`).

**Rotate `AUDIT_IP_SALT`** — acceptable; historical IP hashes stop matching
new ones (they become unlinkable, which is the point of the salt). Change in
`.env.prod` and `up -d` the api service.

**Rotate TLS certificates** — nothing to do; Caddy renews automatically.

**Database was breached (worst day)** — assume all secrets in `.env.prod` are
known: rotate `POSTGRES_PASSWORD` (and restore the DB from the pre-breach
dump if data was modified). Vault contents remain encrypted (zero-knowledge),
but **TOTP secrets are recoverable** from a DB leak and account-password
hashes are crackable offline for weak passwords — notify users, require
password changes (the API has no forced-reset flow; see Limitations in the
README).

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `/ready` 503 | DB unreachable: `docker compose logs db`; check `POSTGRES_PASSWORD` in `.env.prod` matches the db service |
| Caddy issues no certificate | DNS doesn't point at the host yet, or ports 80/443 blocked |
| Web loads but API calls 404 | `API_ORIGIN` mismatch — must be `http://api:3001` inside compose |
| Login works, passkeys don't | `WEBAUTHN_RP_ID`/`WEBAUTHN_ORIGIN` must equal the public domain exactly (`https://domain`) |
| Passkeys fail after domain change | passkeys are bound to the RP ID; they cannot migrate — users must register new ones |
| Cleanup not pruning | check `SNAPSHOT_RETENTION_COUNT` in the api container's env (`docker compose exec api env`) |
