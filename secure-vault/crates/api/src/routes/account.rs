//! Account deletion.
//!
//! Deleting a user row cascades to the vault, vault snapshots, devices,
//! passkeys and sessions — the encrypted data is gone for good (zero-knowledge
//! means there is no server-side copy to "recover"). Audit events are
//! `ON DELETE CASCADE` too, which would erase the very records that prove the
//! deletion happened, so they are re-pointed at a synthetic tombstone account
//! (`00000000-0000-0000-0000-000000000000`) inside the same transaction. The
//! tombstone is created lazily by the caller (`ensure_tombstone`).
//!
//! Self-service deletion re-confirms the **account password** (the last
//! thing an attacker with a stolen session should be able to do silently),
//! revokes every session, and logs `ACCOUNT_DELETED` before the row goes.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::errors::AppError;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;

/// Synthetic account that owns audit events of deleted users. UUID v4 is
/// random; these sixteen bytes are the well-known all-zero UUID and can never
/// collide with a real account.
pub const TOMBSTONE_USER_ID: Uuid = Uuid::from_u128(0);

/// Idempotently create the tombstone account that owns orphaned audit events.
/// It holds no credentials (NULL password hash), has the `tombstone` role, and
/// cannot sign in.
async fn ensure_tombstone(state: &AppState) -> Result<(), AppError> {
    sqlx::query(
        r#"
        INSERT INTO users (id, email, password_hash, role)
        VALUES ($1, $2, NULL, 'tombstone')
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(TOMBSTONE_USER_ID)
    .bind("deleted-account@tombstone.invalid")
    .execute(&state.pool)
    .await?;
    Ok(())
}

#[derive(Deserialize)]
pub struct DeleteAccountRequest {
    /// Confirmation: the account password (not the vault master password).
    pub password: String,
}

/// DELETE /api/v1/account — delete the caller's own account and all its data.
///
/// Requires a full (non-2FA-pending) session plus the account password. The
/// response clears the session cookie. Deletion is immediate and permanent.
pub async fn delete_account(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(req): Json<DeleteAccountRequest>,
) -> Result<(StatusCode, axum::http::HeaderMap, Json<serde_json::Value>), AppError> {
    let row = sqlx::query("SELECT email, password_hash FROM users WHERE id = $1")
        .bind(auth_user.user_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;

    let email: String = row.try_get("email").map_err(|_| AppError::NotFound)?;
    let password_hash: Option<String> = row
        .try_get("password_hash")
        .map_err(|_| AppError::NotFound)?;

    // Tombstone accounts (or any future account without a password) cannot
    // be deleted through this route — they are not real accounts.
    let password_hash = password_hash
        .ok_or_else(|| AppError::Validation("This account cannot be deleted".into()))?;

    let valid = secure_vault_crypto::verify_password(&req.password, &password_hash)
        .map_err(|e| AppError::Crypto(e.to_string()))?;
    if !valid {
        secure_vault_audit::log_event_with_ip(
            &state.pool,
            auth_user.user_id,
            "ACCOUNT_DELETE_FAILED",
            None,
            None,
        )
        .await?;
        return Err(AppError::Unauthorized);
    }

    ensure_tombstone(&state).await?;
    delete_user(&state, auth_user.user_id, "ACCOUNT_DELETED_SELF").await?;

    // Clear the caller's cookie; the session row is already gone via cascade.
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::SET_COOKIE,
        crate::routes::auth::session_cookie(&state, "", 0)
            .parse()
            .map_err(|_| AppError::Internal(anyhow::anyhow!("failed to build cookie")))?,
    );

    Ok((
        StatusCode::OK,
        headers,
        Json(json!({
            "message": "Account and all encrypted vault data permanently deleted",
            "email": email,
        })),
    ))
}

/// DELETE /api/v1/admin/users/:user_id/account — admin-initiated deletion.
/// Admins delete **other** accounts; they cannot delete themselves here (use
/// the self-service route, which requires the password), and they cannot
/// delete the last remaining admin.
pub async fn admin_delete_account(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Path(user_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    crate::middleware::auth::ensure_admin(&auth_user)?;

    if user_id == auth_user.user_id {
        return Err(AppError::Validation(
            "Admins cannot delete their own account via the admin route — use DELETE /account"
                .into(),
        ));
    }

    let row = sqlx::query("SELECT email, role FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;
    let email: String = row.try_get("email").map_err(|_| AppError::NotFound)?;
    let role: String = row.try_get("role").map_err(|_| AppError::NotFound)?;

    if role == "admin" {
        let admins: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            .fetch_one(&state.pool)
            .await?;
        if admins <= 1 {
            return Err(AppError::Conflict(
                "Cannot delete the last remaining admin account".into(),
            ));
        }
    }

    ensure_tombstone(&state).await?;
    delete_user(&state, user_id, "ACCOUNT_DELETED_ADMIN").await?;

    Ok(Json(json!({
        "message": "Account and all encrypted vault data permanently deleted",
        "deleted_user_id": user_id,
        "email": email,
    })))
}

/// The shared deletion transaction: re-point audit events at the tombstone,
/// audit the deletion itself, then delete the user (cascading to the vault,
/// snapshots, devices, passkeys and sessions).
async fn delete_user(state: &AppState, user_id: Uuid, event_type: &str) -> Result<(), AppError> {
    let mut tx = state.pool.begin().await?;

    // Preserve the audit trail of the user we are about to destroy. (The
    // tombstone row is guaranteed to exist by `ensure_tombstone` above.)
    sqlx::query("UPDATE audit_events SET user_id = $2 WHERE user_id = $1")
        .bind(user_id)
        .bind(TOMBSTONE_USER_ID)
        .execute(&mut *tx)
        .await?;

    // The deletion record itself is written against the tombstone — the
    // victim's row is about to disappear, so the event must outlive it.
    sqlx::query(
        r#"
        INSERT INTO audit_events (id, user_id, device_id, event_type, metadata)
        VALUES ($1, $2, NULL, $3, $4)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(TOMBSTONE_USER_ID)
    .bind(event_type)
    .bind(json!({ "deleted_user_id": user_id }))
    .execute(&mut *tx)
    .await?;

    // Cascades: vaults, vault_snapshots, devices, passkeys, sessions.
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}
