-- Account deletion tombstone: audit events of deleted users are re-pointed at
-- this synthetic account (all-zero UUID) so the audit trail outlives the user
-- it describes. The row is created lazily by the deletion code path.
ALTER TABLE users DROP CONSTRAINT users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('user', 'admin', 'tombstone'));
