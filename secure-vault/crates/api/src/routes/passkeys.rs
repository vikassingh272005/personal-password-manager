//! WebAuthn passkey routes.
//!
//! Two ceremonies, both challenge-bound and single-use:
//!
//! - **Register** (authenticated session): add a passkey to the account as a
//!   second factor. The browser signs with Touch ID / Windows Hello / a
//!   security key; the server verifies the attestation and stores the
//!   credential's public key.
//! - **Authenticate** (public): sign in with a passkey instead of a password.
//!   Supports usernameless flows (empty `email` → discoverable credential)
//!   and email-scoped flows. A verified assertion creates a FULL session
//!   (user verification is required on every assertion), audit-logged as
//!   `LOGIN_PASSKEY`.
//!
//! The client must also confirm vault ownership — a passkey proves the
//! *account*, but the vault keys still require the master password or Secret
//! Key in the browser.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::errors::AppError;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use secure_vault_webauthn::cose::CoseKey;
use secure_vault_webauthn::{b64url_decode, b64url_encode, RpConfig};

fn rp_config(state: &AppState) -> RpConfig {
    RpConfig::from_options(
        state.config.webauthn_rp_id.clone(),
        state.config.webauthn_origin.clone(),
    )
}

struct StoredPasskey {
    user_id: Uuid,
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
    sign_count: i64,
}

async fn load_passkey(
    state: &AppState,
    credential_id: &[u8],
) -> Result<Option<StoredPasskey>, AppError> {
    let row = sqlx::query(
        "SELECT user_id, credential_id, public_key, sign_count FROM passkeys WHERE credential_id = $1 AND revoked_at IS NULL",
    )
    .bind(credential_id)
    .fetch_optional(&state.pool)
    .await?;
    Ok(row.map(|row| StoredPasskey {
        user_id: row.get("user_id"),
        credential_id: row.get("credential_id"),
        public_key: row.get("public_key"),
        sign_count: row.get::<i64, _>("sign_count"),
    }))
}

// ---- Registration (second factor) ------------------------------------------

/// POST /auth/passkeys/register/options — start adding a passkey.
pub async fn register_options(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(auth_user.user_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|_| AppError::NotFound)?;

    let options = secure_vault_webauthn::registration_options(
        &rp_config(&state),
        auth_user.user_id.as_bytes(),
        &email,
    );
    let challenge = options["challenge"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let ceremony_id = state.insert_passkey_challenge(Some(email), challenge);

    Ok(Json(
        json!({ "ceremony_id": ceremony_id, "options": options }),
    ))
}

#[derive(Deserialize)]
pub struct RegisterFinishRequest {
    pub ceremony_id: String,
    /// `navigator.credentials.create()` response fields, base64url.
    pub credential_id: String,
    pub attestation_object: String,
    pub client_data_json: String,
    /// Friendly label shown in Settings.
    #[serde(default)]
    pub name: Option<String>,
}

/// POST /auth/passkeys/register/finish — verify and store the new passkey.
pub async fn register_finish(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let pending = state
        .take_passkey_challenge(&req.ceremony_id)
        .ok_or_else(|| AppError::Validation("Passkey ceremony expired — start again".into()))?;
    // The ceremony may only complete for the account that started it.
    let caller_email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(auth_user.user_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|_| AppError::NotFound)?;
    if pending.email.as_deref() != Some(caller_email.as_str()) {
        return Err(AppError::Validation(
            "Ceremony belongs to another account".into(),
        ));
    }

    let rp = rp_config(&state);
    let verified = secure_vault_webauthn::verify_registration(
        &rp,
        &pending.challenge,
        &req.credential_id,
        &req.attestation_object,
        &req.client_data_json,
    )
    .map_err(|e| AppError::Validation(format!("Passkey registration failed: {e}")))?;

    // A credential id must be globally unique — never re-registerable.
    let duplicate = load_passkey(&state, &verified.credential_id).await?;
    if duplicate.is_some() {
        return Err(AppError::Conflict(
            "This passkey is already registered".into(),
        ));
    }

    sqlx::query(
        "INSERT INTO passkeys (user_id, credential_id, public_key, sign_count, name) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(auth_user.user_id)
    .bind(&verified.credential_id)
    .bind(&verified.public_key_cose)
    .bind(verified.sign_count as i64)
    .bind(req.name.as_deref().unwrap_or("This device"))
    .execute(&state.pool)
    .await?;

    secure_vault_audit::log_event(&state.pool, auth_user.user_id, "PASSKEY_REGISTERED", None)
        .await?;

    Ok(Json(
        json!({ "registered": true, "message": "Passkey added to your account" }),
    ))
}

// ---- Authentication (passkey-only sign-in) ---------------------------------

/// POST /auth/passkeys/login/options — start a sign-in ceremony. Empty body or
/// no `email` = discoverable (usernameless) sign-in.
#[derive(Deserialize, Default)]
pub struct LoginOptionsRequest {
    #[serde(default)]
    pub email: Option<String>,
}

pub async fn login_options(
    State(state): State<AppState>,
    Json(req): Json<LoginOptionsRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Collect the allow-list: the user's active passkeys when an email was
    // given, or none (browser picks any discoverable credential for this RP).
    let mut allow: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(email) = req
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        let rows = sqlx::query(
            "SELECT p.credential_id FROM passkeys p JOIN users u ON u.id = p.user_id \
             WHERE u.email = $1 AND p.revoked_at IS NULL",
        )
        .bind(email)
        .fetch_all(&state.pool)
        .await?;
        allow = rows
            .into_iter()
            .map(|row| {
                let id: Vec<u8> = row.get("credential_id");
                (b64url_encode(&id), id)
            })
            .collect();
    }

    let options = secure_vault_webauthn::authentication_options(&allow);
    let challenge = options["challenge"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let ceremony_id = state.insert_passkey_challenge(req.email.clone(), challenge);

    Ok(Json(
        json!({ "ceremony_id": ceremony_id, "options": options }),
    ))
}

#[derive(Deserialize)]
pub struct LoginFinishRequest {
    pub ceremony_id: String,
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}

/// POST /auth/passkeys/login/finish — verify the assertion and sign in.
pub async fn login_finish(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<LoginFinishRequest>,
) -> Result<(StatusCode, axum::http::HeaderMap, Json<serde_json::Value>), AppError> {
    let pending = state
        .take_passkey_challenge(&req.ceremony_id)
        .ok_or_else(|| AppError::Validation("Passkey ceremony expired — start again".into()))?;

    let credential_id = b64url_decode(&req.credential_id)
        .map_err(|_| AppError::Validation("invalid credential id".into()))?;
    let stored = load_passkey(&state, &credential_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    // Email-scoped ceremonies may only complete with that account's passkey.
    if let Some(email) = &pending.email {
        let match_email: Option<String> = sqlx::query_scalar(
            "SELECT u.email FROM users u JOIN passkeys p ON p.user_id = u.id WHERE p.credential_id = $1",
        )
        .bind(&stored.credential_id)
        .fetch_optional(&state.pool)
        .await?;
        if match_email.as_deref() != Some(email.as_str()) {
            return Err(AppError::Unauthorized);
        }
    }

    let rp = rp_config(&state);
    let public_key = parse_stored_key(&stored.public_key)?;
    let new_count = secure_vault_webauthn::verify_authentication(
        &rp,
        &pending.challenge,
        &public_key,
        stored.sign_count as u32,
        &req.authenticator_data,
        &req.client_data_json,
        &req.signature,
    )
    .map_err(|e| {
        tracing::warn!("passkey assertion rejected for credential: {e}");
        AppError::Unauthorized
    })?;

    sqlx::query(
        "UPDATE passkeys SET sign_count = $2, last_used_at = NOW() WHERE credential_id = $1",
    )
    .bind(&stored.credential_id)
    .bind(new_count as i64)
    .execute(&state.pool)
    .await?;

    // Full session: the assertion carried user verification.
    let session_token =
        secure_vault_auth::create_session(&state.pool, stored.user_id, None).await?;
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(stored.user_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|_| AppError::NotFound)?;
    let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
        .bind(stored.user_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|_| AppError::NotFound)?;

    secure_vault_audit::log_event(&state.pool, stored.user_id, "LOGIN_PASSKEY", None).await?;

    let mut response_headers = axum::http::HeaderMap::new();
    let cookie = crate::routes::auth::session_cookie(&session_token, 24 * 3600);
    response_headers.insert(
        axum::http::header::SET_COOKIE,
        cookie
            .parse()
            .map_err(|_| AppError::Internal(anyhow::anyhow!("cookie encoding")))?,
    );
    let _ = headers; // reserved: future IP logging for audit events

    Ok((
        StatusCode::OK,
        response_headers,
        Json(json!({
            "user_id": stored.user_id,
            "email": email,
            "role": role,
            "message": "Signed in with passkey"
        })),
    ))
}

fn parse_stored_key(bytes: &[u8]) -> Result<CoseKey, AppError> {
    secure_vault_webauthn::cose::parse_cose_key(bytes)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("stored passkey has an unreadable key")))
}

// ---- Listing & revoking ----------------------------------------------------

/// GET /auth/passkeys — the caller's registered passkeys.
pub async fn list_passkeys(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let rows = sqlx::query(
        "SELECT id, name, created_at::timestamptz, last_used_at::timestamptz FROM passkeys \
         WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC",
    )
    .bind(auth_user.user_id)
    .fetch_all(&state.pool)
    .await?;

    let passkeys: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.get::<Uuid, _>("id"),
                "name": row.get::<Option<String>, _>("name"),
                "created_at": row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("created_at"),
                "last_used_at": row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_used_at"),
            })
        })
        .collect();

    Ok(Json(json!({ "passkeys": passkeys })))
}

/// DELETE /auth/passkeys/:id — revoke one passkey.
pub async fn revoke_passkey(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    axum::extract::Path(passkey_id): axum::extract::Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let result = sqlx::query(
        "UPDATE passkeys SET revoked_at = NOW() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(passkey_id)
    .bind(auth_user.user_id)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    secure_vault_audit::log_event(&state.pool, auth_user.user_id, "PASSKEY_REVOKED", None).await?;
    Ok(Json(json!({ "revoked": true })))
}
