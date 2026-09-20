-- Two-factor authentication (TOTP, RFC 6238).
--
-- The TOTP secret is stored *reversibly* (unlike a password hash) because the
-- server must be able to compute the expected code at login time. This is the
-- standard trade-off for server-side TOTP; the secret is independent of the
-- vault keys, so a leaked totp_secret still leaves every vault item encrypted.
--
-- Sessions gain `awaiting_2fa`: after a correct password against an account
-- with 2FA enabled, the session is created in a restricted state that only
-- the 2FA challenge endpoint accepts, and is flipped to fully valid once the
-- code is verified. The `AuthenticatedUser` extractor rejects sessions still
-- awaiting 2FA, so no other endpoint is reachable with a half-login.

ALTER TABLE users
    ADD COLUMN totp_secret TEXT,
    ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN totp_pending_secret TEXT;

ALTER TABLE sessions
    ADD COLUMN awaiting_2fa BOOLEAN NOT NULL DEFAULT FALSE;
