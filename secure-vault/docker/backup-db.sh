#!/bin/sh
# Encrypted-at-rest optional nightly backup: dumps the production database
# with pg_dump (custom format, compressed) inside the db container and writes
# the file to a host-mounted backup directory.
#
# Usage (on the host):
#   ./docker/backup-db.sh [output-dir]
#
# Schedule with cron:
#   15 4 * * *  cd /srv/securevault && ./docker/backup-db.sh /srv/backups >> /var/log/sv-backup.log 2>&1
#
# See docs/operations.md for restore and retention guidance.

set -eu

BACKUP_DIR="${1:-./backups}"
STAMP="$(date +%Y%m%d-%H%M%S)"
KEEP_DAYS="${BACKUP_RETENTION_DAYS:-14}"

mkdir -p "$BACKUP_DIR"

echo "[backup] dumping database…"
docker compose -f docker-compose.prod.yml exec -T db \
    pg_dump -U securevault -d secure_vault -Fc \
    > "$BACKUP_DIR/secure_vault-$STAMP.dump"

echo "[backup] wrote $BACKUP_DIR/secure_vault-$STAMP.dump"

# Local retention: keep the newest $KEEP_DAYS days of dumps.
if [ "$KEEP_DAYS" -gt 0 ]; then
    find "$BACKUP_DIR" -name 'secure_vault-*.dump' -mtime +"$KEEP_DAYS" -print -delete |
        sed 's/^/[backup] pruned old dump: /'
fi

echo "[backup] done."
echo
echo "NOTE: the dump contains password hashes, TOTP secrets and ciphertext —"
echo "it is sensitive even though vault items are zero-knowledge. Copy it to"
echo "off-site storage (e.g. 'rclone copy' to object storage) and keep the"
echo "transport encrypted. Verify restores monthly (see docs/operations.md)."
