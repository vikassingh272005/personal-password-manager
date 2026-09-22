# ADR 0005 — Passphrase-encrypted, client-side export/import

- Status: accepted
- Date: 2026-09

## Context

Settings exposed disabled Export / Import / Delete placeholders. Export/import
must not violate the zero-knowledge invariant: no plaintext vault file may
reach the server (or be readable by it), and the format must be self-verifying
and decryptable years from now, independent of this server's existence.

## Decision

Client-side only: `lib/vaultTransfer.ts` builds a JSON file containing the
envelope (items + folders) encrypted with AES-256-GCM under a key derived
from a user passphrase via PBKDF2-SHA256 (310k iterations, per-file random
16-byte salt). The file embeds `format: "secure-vault-export"`, version,
KDF parameters and cipher so future importers can validate before decrypting.
Import decrypts locally, skips items whose IDs already exist (no silent
overwrite), and merges folders; the normal sync flow uploads the merged
snapshot. The server sees only the resulting ciphertext, like any other sync.

## Alternatives considered

- **Server-side export endpoint** handing out the raw snapshot. Simpler, but
  the file would be decryptable only inside this app (needs the user's key
  hierarchy), defeating the "leave the platform" purpose.
- **HTML/CSV export** for interop with other managers. Rejected for v1:
  plaintext credential files; can be offered later as an explicitly-warned,
  client-side "insecure CSV" option.

## Consequences

- Losing the export passphrase loses the backup (GCM tag makes brute-force
  infeasible; there is no recovery) — the UI says so.
- The format is independent of the account/master password, so it remains
  usable even if this server disappears entirely.
