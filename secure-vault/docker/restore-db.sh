#!/bin/sh
# Restore a pg_dump created by docker/backup-db.sh.
#
# Usage:
#   ./docker/restore-db.sh <path-to-dump> [--force]
#
# The script refuses to run without --force when the target database already
# contains accounts: a restore OVERWRITES the live database.

set -eu

DUMP="${1:?usage: restore-db.sh <dump-file> [--force]}"
FORCE="${2:-}"

[ -f "$DUMP" ] || { echo "dump file not found: $DUMP" >&2; exit 1; }

USERS=$(docker compose -f docker-compose.prod.yml exec -T db \
    psql -U securevault -d secure_vault -tAc "SELECT COUNT(*) FROM users" 2>/dev/null || echo 0)

if [ "$USERS" != "0" ] && [ "$FORCE" != "--force" ]; then
    echo "WARNING: the database already contains $USERS account(s)." >&2
    echo "A restore drops the current data. Re-run with --force to proceed:" >&2
    echo "  $0 $DUMP --force" >&2
    exit 1
fi

echo "[restore] stopping the API to prevent writes during restore…"
docker compose -f docker-compose.prod.yml stop api

echo "[restore] recreating database from $DUMP…"
docker compose -f docker-compose.prod.yml exec -T db psql -U postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='secure_vault'" >/dev/null 2>&1 || true
docker compose -f docker-compose.prod.yml exec -T db dropdb -U securevault --if-exists secure_vault || true
docker compose -f docker-compose.prod.yml exec -T db psql -U securevault -d postgres -c "CREATE DATABASE secure_vault OWNER securevault"

docker compose -f docker-compose.prod.yml exec -T db \
    pg_restore -U securevault -d secure_vault --no-owner --role=securevault "$DUMP" 2>/dev/null || \
    docker cp "$(pwd)/$DUMP" "$(docker compose -f docker-compose.prod.yml ps -q db)":/tmp/restore.dump

echo "[restore] starting the API again (it runs pending migrations at boot)…"
docker compose -f docker-compose.prod.yml up -d api

echo "[restore] done. Verify with: curl -fsS https://\$(grep ^DOMAIN .env.prod | cut -d= -f2)/ready"
