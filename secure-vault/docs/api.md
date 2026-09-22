# API Reference

Base URL: `/api/v1`

All bodies are JSON. Errors use `{ "error": "..." }` with meaningful status
codes (401/403/404/400/409/413/429/500). Request bodies are capped at 2 MiB
(413 above that). The session cookie is `HttpOnly; SameSite=Lax`, plus
`Secure` when `APP_ENV=production`.

## Authentication

### POST /auth/register
```json
{ "email": "...", "password": "..." }
```
Creates an account (Argon2id-hashed password, ≥12 chars, RFC-style email
check) and an empty encrypted vault; returns KDF parameters for the client
to derive its KEK. The master password is **never transmitted or stored**.
The first registered account becomes admin only outside production.

### POST /auth/login
```json
{ "email": "...", "password": "..." }
```
Returns a session cookie (`202` + `two_factor_required` when TOTP is on).
Responses are timing-equalized for unknown emails; login attempts are
rate-limited per IP.

### POST /auth/logout
Revokes all sessions for the current user.

### GET /auth/refresh
Verifies the current session is valid.

### GET /auth/me
```json
{ "user_id": "...", "email": "...", "role": "user | admin" }
```
Returns the signed-in user's identity and role (used to show/hide the admin console).

## Vault

### GET /vault
Returns **encrypted** vault material (KDF parameters, encrypted VEK). Not plaintext.

```json
{
  "version": 1,
  "kdf_algorithm": "Argon2id",
  "kdf_memory": 65536,
  "kdf_iterations": 3,
  "kdf_parallelism": 2,
  "kdf_salt": "base64",
  "encrypted_vault_key": "base64"
}
```

### PUT /vault
```json
{ "version": 2, "ciphertext": "...", "nonce": "..." }
```
Uploads a new encrypted vault snapshot. Rejects if version is not newer (conflict detection). Each accepted snapshot is persisted to `vault_snapshots` (version, size, ciphertext) and logged as a `VAULT_UPDATED` audit event — content is stored but never decrypted server-side.


## Devices

### GET /devices
List devices for current user.

### POST /devices
```json
{ "name": "...", "device_type": "...", "password": "..." }
```
Register a device.

### DELETE /devices/:id
Revoke a device and its sessions.

## Account

### DELETE /account
```json
{ "password": "..." }
```
Permanently deletes the signed-in account: the encrypted vault, every
snapshot, device, passkey and session are cascaded away in one transaction.
Requires the **account password** (a stolen session alone cannot delete an
account). Audit events are preserved by re-pointing them at a tombstone
account, and an `ACCOUNT_DELETED_SELF` event records the deletion. Clears
the session cookie.

### DELETE /admin/users/:user_id/account
Admin-initiated deletion of **another** account (refuses the acting admin
and the last remaining admin). Audited as `ACCOUNT_DELETED_ADMIN`.

## Admin (role-gated)

All `/admin/*` routes require an `admin` role session; regular users receive `403`. The role is read from the DB on every request, so changes apply immediately.

| Endpoint | Description |
|---|---|
| `GET /admin/overview` | Totals: users, admins, active sessions/devices, vault syncs, events (24h + total), signups 24h — plus the 15 most recent audit events |
| `GET /admin/users` | All accounts with last-active time, device/session/sync counts and vault version |
| `PATCH /admin/users/:id/role` | Body `{ "role": "user" \| "admin" }`. Refuses self-changes and demoting the last admin |
| `POST /admin/users/:id/revoke-sessions` | Revokes every active session of the target user |
| `GET /admin/audit` | Paginated audit feed. Query params: `limit` (≤200, default 50), `offset`, `event_type`, `user_id` |

Admin actions (`ADMIN_ROLE_CHANGED`, `ADMIN_SESSIONS_REVOKED`) are themselves recorded in the audit log with actor + target metadata. Reading the console (overview/users/audit views) is intentionally **not** logged, so browsing never pollutes the feed.

## Security Notes
- Session tokens are hashed before storage (`hash_sha256`).
- Never logs secrets.
- Authentication derived from server-side session, never from request body.
- All vault data is encrypted client-side before reaching these endpoints.
