-- Snapshot retention: the cleanup task keeps the newest
-- SNAPSHOT_RETENTION_COUNT snapshots per user and deletes older ones.
-- The (user_id, version DESC) index from 002 serves reads; this ascending
-- variant lets the retention query walk old rows cheaply when pruning.
CREATE INDEX IF NOT EXISTS idx_vault_snapshots_user_version_asc
    ON vault_snapshots(user_id, version ASC);

COMMENT ON INDEX idx_vault_snapshots_user_version_asc IS
    'Serves the snapshot-retention cleanup (prune all but the newest N per user).';
