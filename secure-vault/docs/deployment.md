# Deployment

SecureVault ships as a four-service stack for a single production host:
**Caddy** (automatic HTTPS) → **web** (Next.js standalone) → **api** (Rust/axum)
→ **Postgres 16**. The API applies SQLx migrations automatically at startup,
so a deployment is: build images → start stack → verify `/ready`.

## What hosts what

| Service | Image | Role |
|---|---|---|
| `caddy` | `caddy:2-alpine` | TLS termination (Let's Encrypt), HTTP→HTTPS redirect, reverse proxy to web |
| `web` | built from `docker/web.Dockerfile` | Next.js UI (standalone output), proxies `/api/*` to the API |
| `api` | built from `docker/api.Dockerfile` | Rust API; runs migrations at boot; enforces auth/rate limits |
| `db` | `postgres:16-alpine` | All persistent data; **not** exposed to the host network |

Local development remains `npm run dev` (dev.mjs); this document is about
production.

## One-time setup

1. **Host** — any small VPS (1 vCPU / 1 GB is fine to start) with Docker +
   the compose plugin. Open ports 22, 80, 443.
2. **DNS** — point an `A`/`AAAA` record at the host (this becomes `DOMAIN`).
   HTTPS is issued automatically by Caddy via HTTP-01, so the record must be
   live before first start.
3. **Checkout** — clone the repo to e.g. `/srv/securevault`.
4. **Secrets** — on the host (never committed):
   ```bash
   cp .env.prod.example .env.prod
   openssl rand -hex 32   # POSTGRES_PASSWORD
   openssl rand -hex 32   # SESSION_SECRET
   openssl rand -hex 32   # AUDIT_IP_SALT
   # fill DOMAIN, ACME_EMAIL, and the three secrets into .env.prod
   ```
   `SESSION_SECRET` and `AUDIT_IP_SALT` must be stable across restarts
   (the salt keeps audit IP hashes correlatable). Rotating `SESSION_SECRET`
   invalidates nothing today (tokens are random, not signed) but treat it as
   secret anyway.
5. **First admin** — production deliberately has **no first-user-becomes-admin
   bootstrap**. Register your account through the UI, then promote it:
   ```bash
   docker compose --env-file .env.prod -f docker-compose.prod.yml exec db \
     psql -U securevault -d secure_vault \
     -c "UPDATE users SET role='admin' WHERE email='you@example.com';"
   ```
   (Or list the address in `ADMIN_EMAILS` in `.env.prod` before registering.)

## Deploy / update

```bash
cd /srv/securevault
git pull --ff-only
docker compose --env-file .env.prod -f docker-compose.prod.yml up -d --build
```

Migration safety: the API runs `sqlx::migrate!` at startup — exactly once per
version bump, in the container's entrypoint, before it serves traffic. There
is no separate migration step to run by hand, and no developer ever edits the
production database manually (the admin role/bootstrap above is the one
documented exception, done via `psql` in the container).

The GitHub Actions `Deploy` workflow (`.github/workflows/deploy.yml`) automates
exactly this once you set the `DEPLOY_*` repository secrets; until then it
inertly skips.

## Verify a deployment

```bash
curl -fsS https://your.domain/ready          # {"status":"ready"} = API + DB ok
docker compose --env-file .env.prod -f docker-compose.prod.yml ps   # all healthy
docker logs $(docker compose -f docker-compose.prod.yml ps -q api) | tail
```

Functional smoke test: register a throwaway account in the UI, unlock the
vault, create one item, lock, log in again — then delete the account from
Settings → Data (which also proves the deletion path works).

## Rollback

Images are rebuilt from the checked-out commit, so roll back by checking out
the previous tag/commit and `up -d --build` again. Because migrations are
applied forward-only, a rollback of *code* is always safe; a rollback across
a migration that the previous code cannot read is not supported (see
`docs/architecture.md` for the schema-evolution policy — keep new columns
nullable / additive).

## Where things live on the host

| Thing | Location |
|---|---|
| Application code | `/srv/securevault` (the git checkout) |
| Database data | named volume `secure-vault_db_data` |
| TLS certificates | named volume `secure-vault_caddy_data` |
| Database backups | wherever `docker/backup-db.sh` writes them (see `docs/operations.md`) |
| Secrets | `.env.prod` (chmod 600, git-ignored) |
