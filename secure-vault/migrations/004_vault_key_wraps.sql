-- Two-layer key hierarchy: the vault is encrypted under a random per-vault
-- VEK (vault encryption key). The master password only derives a KEK that
-- *wraps* the VEK; a "Secret Key" recovery kit wraps the same VEK under an
-- independent key. The server stores both wraps (never the keys themselves).
-- A vault row with kek_wrap_ciphertext IS NULL is either a legacy vault
-- (items encrypted directly under a PBKDF2 key derived from the master
-- password) or an uninitialized vault row created before the client uploaded
-- its first snapshot.
ALTER TABLE vaults
    ADD COLUMN kek_wrap_ciphertext BYTEA,
    ADD COLUMN kek_wrap_nonce BYTEA,
    ADD COLUMN recovery_wrap_ciphertext BYTEA,
    ADD COLUMN recovery_wrap_nonce BYTEA;

-- Defense in depth for the version check in PUT /vault: the transaction's
-- FOR UPDATE row lock serializes uploads, but a unique constraint guarantees
-- no duplicate snapshot version can ever be inserted, whatever the client.
CREATE UNIQUE INDEX idx_vault_snapshots_user_version_unique
    ON vault_snapshots(user_id, version);
