use anyhow::Result;
use chrono::{Duration, Utc};
use sqlx::Row;
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use secure_vault_crypto::{generate_random_string, hash_sha256, verify_password};

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Session expired")]
    SessionExpired,
    #[error("Account suspended")]
    AccountSuspended,
}

pub async fn create_session(
    pool: &PgPool,
    user_id: Uuid,
    device_id: Option<Uuid>,
) -> Result<String> {
    let session_token = generate_random_string(64);
    let token_hash = hash_sha256(session_token.as_bytes());
    let expires_at = Utc::now() + Duration::hours(24);

    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, token_hash, device_id, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(&token_hash)
    .bind(device_id)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(session_token)
}

pub async fn validate_session(pool: &PgPool, session_token: &str) -> Result<Uuid, AuthError> {
    let token_hash = hash_sha256(session_token.as_bytes());

    let row = sqlx::query(
        r#"
        SELECT user_id, expires_at::timestamptz, revoked_at::timestamptz
        FROM sessions
        WHERE token_hash = $1
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await
    .map_err(|_| AuthError::InvalidCredentials)?;

    let row = row.ok_or(AuthError::InvalidCredentials)?;

    let user_id: Uuid = row.try_get("user_id").map_err(|_| AuthError::InvalidCredentials)?;
    let expires_at: chrono::DateTime<Utc> = row
        .try_get("expires_at")
        .map_err(|_| AuthError::InvalidCredentials)?;
    let revoked_at: Option<chrono::DateTime<Utc>> = row
        .try_get("revoked_at")
        .map_err(|_| AuthError::InvalidCredentials)?;

    if revoked_at.is_some() {
        return Err(AuthError::InvalidCredentials);
    }

    if expires_at < Utc::now() {
        return Err(AuthError::SessionExpired);
    }

    Ok(user_id)
}

pub async fn revoke_session(pool: &PgPool, session_token: &str) -> Result<()> {
    let token_hash = hash_sha256(session_token.as_bytes());

    sqlx::query(
        "UPDATE sessions SET revoked_at = NOW() WHERE token_hash = $1 AND revoked_at IS NULL",
    )
    .bind(&token_hash)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn revoke_all_user_sessions(pool: &PgPool, user_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn authenticate(
    pool: &PgPool,
    email: &str,
    password: &str,
) -> Result<Uuid, AuthError> {
    let row = sqlx::query("SELECT id, password_hash FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(pool)
        .await
        .map_err(|_| AuthError::InvalidCredentials)?;

    let row = row.ok_or(AuthError::InvalidCredentials)?;

    let user_id: Uuid = row.try_get("id").map_err(|_| AuthError::InvalidCredentials)?;
    let password_hash: Option<String> = row
        .try_get("password_hash")
        .map_err(|_| AuthError::InvalidCredentials)?;

    let password_hash = password_hash.ok_or(AuthError::InvalidCredentials)?;

    let valid = verify_password(password, &password_hash)
        .map_err(|_| AuthError::InvalidCredentials)?;

    if !valid {
        return Err(AuthError::InvalidCredentials);
    }

    Ok(user_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_string_is_unique() {
        let a = generate_random_string(64);
        let b = generate_random_string(64);
        assert_ne!(a, b);
    }

    #[test]
    fn test_token_hash_deterministic() {
        let token = "test-token";
        let h1 = hash_sha256(token.as_bytes());
        let h2 = hash_sha256(token.as_bytes());
        assert_eq!(h1, h2);
    }
}
