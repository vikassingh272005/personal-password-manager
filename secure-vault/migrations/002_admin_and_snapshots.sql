-- Admin roles: users can be 'user' or 'admin'.
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('user', 'admin'));

-- Vault sync history: every accepted PUT /vault persists the ciphertext snapshot,
-- so sync activity ("what entries are being made") is observable server-side.
CREATE TABLE vault_snapshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    blob_size INTEGER NOT NULL,
    ciphertext BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_vault_snapshots_user_id_version ON vault_snapshots(user_id, version DESC);
CREATE INDEX idx_vault_snapshots_created_at ON vault_snapshots(created_at DESC);

-- Indexes to make admin audit queries fast.
CREATE INDEX idx_audit_events_created_at ON audit_events(created_at DESC);
CREATE INDEX idx_audit_events_event_type ON audit_events(event_type);
