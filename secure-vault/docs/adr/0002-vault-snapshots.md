# ADR 0002 — Whole-vault encrypted snapshots over per-item rows

- Status: accepted
- Date: 2026-09

## Context

The server must never see plaintext items (zero-knowledge). Two storage
models are possible: per-item encrypted rows (server-side item CRUD over
ciphertext) or whole-vault encrypted snapshots synced as versioned blobs.

## Decision

Whole-vault encrypted snapshots (`vault_snapshots`, one row per accepted
`PUT /vault`), with key wraps stored on the `vaults` row. The client owns
item CRUD against its decrypted copy; the server stores and versions opaque
blobs.

## Rationale

- The server cannot index or query encrypted per-item rows anyway, so a
  per-item API would add endpoints without capability.
- Conflict resolution is explicit and client-side: version + 1 required,
  `409` otherwise, client re-downloads and re-merges. Simple to reason about.
- One GCM envelope per sync keeps the crypto surface minimal.

## Alternatives considered

- **Per-item encrypted rows** (Bitwarden-style server model). More granular
  history and partial syncs, at the cost of a much larger server API, harder
  server-side integrity rules, and no practical benefit while the client
  already holds the whole decrypted vault in memory.

## Consequences

- Sync history IS the backup surface: snapshot retention
  (`SNAPSHOT_RETENTION_COUNT`, cleanup in `maintenance.rs`) bounds growth
  while keeping a rollback window; the newest snapshot is never pruned.
- Search/analytics server-side are impossible by design (that is the point).
- A future "shared vault" feature would need per-item or per-collection
  envelopes; that is a breaking change to the envelope, not to the schema.
