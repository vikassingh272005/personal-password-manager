# Deployment

## Local Development

```bash
docker compose up -d    # PostgreSQL + Redis
cargo run -p secure-vault-api
# frontend:
cd apps/web && npm install && npm run dev
```

Health checks:
- `GET /health` — liveness
- `GET /ready` — readiness (checks DB connection)

## Production Configuration

Set environment variables (never commit real values):
```
DATABASE_URL=postgres://...
SESSION_SECRET=<long-random-secret>
PORT=3001
CORS_ORIGINS=https://app.yourdomain.com
WEBAUTHN_RP_ID=yourdomain.com
WEBAUTHN_ORIGIN=https://app.yourdomain.com
APP_ENV=production
```

## Database

Production database security:
- Dedicated application role (least privilege, not `postgres` superuser)
- Separate migration role
- TLS database connections
- Encrypted backups
- Restricted network access

Migrations are versioned in `migrations/`. Never modify an applied migration; add a new one.

## Reverse Proxy

Place behind a TLS-terminating reverse proxy (nginx/Caddy/cloudfront) for HTTPS. Set `trusted` proxy headers accordingly.

## Backup

- PostgreSQL point-in-time recovery
- Encrypted backups (the vault contents are already zero-knowledge, but DB still contains user PII and auth hashes)

## CI/CD

Pipeline runs:
```bash
cargo fmt --check
cargo clippy
cargo test
cargo audit
# frontend
npm run lint
npm run build
```

## Before Production

- Run full test suite
- cargo audit / dependency review
- Review auth, authorization, crypto
- Verify no secrets logged
- Verify ciphertext tampering detection
- Verify session/device/passkey revocation
- External security review

Do not claim "unhackable" or "100% secure." Use precise security claims.
