-- Real vault sync: snapshots must retain the AES-GCM nonce (IV) so the blob
-- can actually be decrypted on unlock.
ALTER TABLE vault_snapshots ADD COLUMN nonce BYTEA;

-- The vault data key is derived in the browser (WebCrypto PBKDF2), because the
-- original scaffold wrapped the vault key with an Argon2id-derived KEK that a
-- browser can never reproduce. Vaults created by that scheme are re-keyed to
-- PBKDF2-SHA256 with OWASP-recommended parameters. No snapshot ever existed
-- under the old scheme, so discarding the placeholder wrapped key loses no data;
-- the per-user kdf_salt is preserved, so the user's master password still works.
UPDATE vaults
SET kdf_algorithm = 'PBKDF2-SHA256',
    kdf_iterations = 310000,
    kdf_memory = 0,
    kdf_parallelism = 0,
    encrypted_vault_key = decode(md5(random()::text) || md5(random()::text), 'hex')
WHERE kdf_algorithm = 'Argon2id';
