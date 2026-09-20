use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::Json;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::errors::AppError;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub user_id: Uuid,
    pub email: String,
    pub role: String,
    pub message: String,
    /// True when the password was accepted but a TOTP challenge must be
    /// completed (POST /auth/2fa/challenge) before the session is usable.
    pub two_factor_required: bool,
}

/// Register response carries the vault KDF parameters the client needs to
/// derive its KEK and upload the first wrapped snapshot in the same breath
/// (the vault row exists server-side before the browser has done any crypto).
#[derive(Serialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub email: String,
    pub role: String,
    pub message: String,
    pub kdf_algorithm: String,
    pub kdf_iterations: i32,
    pub kdf_salt: String,
}

#[derive(Serialize)]
pub struct MeResponse {
    pub user_id: Uuid,
    pub email: String,
    pub role: String,
    /// Whether TOTP two-factor is active — the client shows setup state from it.
    pub totp_enabled: bool,
}

fn session_cookie(token: &str, max_age: i64) -> String {
    format!(
        "session_token={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"
    )
}

fn is_admin_email(config: &crate::state::AppState, email: &str) -> bool {
    let email = email.trim().to_lowercase();
    config
        .config
        .admin_emails
        .iter()
        .any(|configured| configured == &email)
}

/// Insert a 24h session and return its raw token (the caller sets the
/// cookie). Sessions for accounts with 2FA start as `awaiting_2fa` and are
/// activated by the challenge endpoint once the code is verified.
async fn create_session(state: &AppState, user_id: Uuid, awaiting_2fa: bool) -> Result<String, AppError> {
    let session_token = secure_vault_crypto::generate_random_string(64);
    let token_hash = secure_vault_crypto::hash_sha256(session_token.as_bytes());
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);

    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, token_hash, expires_at, awaiting_2fa)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(&token_hash)
    .bind(expires_at)
    .bind(awaiting_2fa)
    .execute(&state.pool)
    .await?;

    Ok(session_token)
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, HeaderMap, Json<RegisterResponse>), AppError> {
    if req.email.is_empty() || req.password.is_empty() {
        return Err(AppError::Validation("All fields are required".into()));
    }

    let existing = sqlx::query("SELECT 1 FROM users WHERE email = $1")
        .bind(&req.email)
        .fetch_optional(&state.pool)
        .await?;

    if existing.is_some() {
        return Err(AppError::Conflict("Email already registered".into()));
    }

    let password_hash = secure_vault_crypto::hash_password(&req.password)
        .map_err(|e| AppError::Crypto(e.to_string()))?;

    // Bootstrap rule: if no ADMIN_EMAILS are configured, the very first
    // account becomes admin (development convenience). Otherwise only emails
    // listed in ADMIN_EMAILS get the role.
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.pool)
        .await?;
    let role = if (state.config.admin_emails.is_empty() && user_count == 0)
        || is_admin_email(&state, &req.email)
    {
        "admin"
    } else {
        "user"
    };

    let user_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO users (id, email, password_hash, role) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(&req.email)
    .bind(&password_hash)
    .bind(role)
    .execute(&state.pool)
    .await?;

    // Vault key material: the client derives its KEK from the master password
    // (PBKDF2-SHA256, browser WebCrypto) using this salt and iteration count,
    // then uploads the wrapped vault key on the first PUT. The master password
    // itself is never sent to the server. encrypted_vault_key is a random
    // placeholder kept for schema compat; the real wrap lives in the
    // kek_wrap_* columns the client populates.
    let kdf_algorithm = "PBKDF2-SHA256";
    let kdf_iterations = 310000i32;
    let kdf_salt = secure_vault_crypto::generate_random_bytes(32);
    let encrypted_vault_key = secure_vault_crypto::generate_random_bytes(32);

    sqlx::query(
        r#"
        INSERT INTO vaults (id, user_id, version, kdf_algorithm, kdf_memory, kdf_iterations, kdf_parallelism, kdf_salt, encrypted_vault_key)
        VALUES ($1, $2, 1, $3, 0, $4, 0, $5, $6)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(kdf_algorithm)
    .bind(kdf_iterations)
    .bind(&kdf_salt)
    .bind(&encrypted_vault_key)
    .execute(&state.pool)
    .await?;

    // The browser needs an authenticated channel immediately (the register
    // page derives the KEK and uploads the first wrapped snapshot before the
    // user leaves), so registration establishes a session like login does.
    // New accounts have no 2FA yet, so the session is fully active.
    let session_token = create_session(&state, user_id, false).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        session_cookie(&session_token, 86400)
            .parse()
            .map_err(|_| AppError::Internal(anyhow::anyhow!("failed to build cookie")))?,
    );

    secure_vault_audit::log_event_with_meta(
        &state.pool,
        user_id,
        "USER_REGISTERED",
        None,
        Some(serde_json::json!({ "role": role })),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        headers,
        Json(RegisterResponse {
            user_id,
            email: req.email.clone(),
            role: role.to_string(),
            message: "Account created successfully".into(),
            kdf_algorithm: kdf_algorithm.to_string(),
            kdf_iterations,
            kdf_salt: base64::engine::general_purpose::STANDARD.encode(&kdf_salt),
        }),
    ))
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<(StatusCode, HeaderMap, Json<AuthResponse>), AppError> {
    let row = sqlx::query(
        "SELECT id, email, password_hash, totp_enabled FROM users WHERE email = $1",
    )
    .bind(&req.email)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::Unauthorized)?;

    let user_id: Uuid = row.try_get("id").map_err(|_| AppError::Unauthorized)?;
    let email: String = row.try_get("email").map_err(|_| AppError::Unauthorized)?;
    let password_hash: Option<String> =
        row.try_get("password_hash").map_err(|_| AppError::Unauthorized)?;
    let password_hash = password_hash.ok_or(AppError::Unauthorized)?;
    let totp_enabled: bool = row
        .try_get("totp_enabled")
        .map_err(|_| AppError::Unauthorized)?;

    let valid = secure_vault_crypto::verify_password(&req.password, &password_hash)
        .map_err(|e| AppError::Crypto(e.to_string()))?;

    if !valid {
        secure_vault_audit::log_event(&state.pool, user_id, "LOGIN_FAILED", None).await?;
        return Err(AppError::Unauthorized);
    }

    // If this account is listed in ADMIN_EMAILS, elevate it now. This makes
    // role assignment possible for accounts created before the env var was set.
    if is_admin_email(&state, &email) {
        sqlx::query(
            "UPDATE users SET role = 'admin', updated_at = NOW() WHERE id = $1 AND role <> 'admin'",
        )
        .bind(user_id)
        .execute(&state.pool)
        .await?;
    }

    let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.pool)
        .await?;

    // With 2FA enabled, the session is created in a restricted "awaiting
    // 2FA" state: only the challenge endpoint accepts it (see the
    // AuthenticatedUser extractor), so half-logins can reach nothing else.
    let session_token = create_session(&state, user_id, totp_enabled).await?;

    if totp_enabled {
        secure_vault_audit::log_event(&state.pool, user_id, "LOGIN_PASSWORD_OK", None).await?;
    } else {
        secure_vault_audit::log_event(&state.pool, user_id, "LOGIN_SUCCESS", None).await?;
    }

    // HttpOnly session cookie. Not marked Secure so local http dev works; add
    // Secure + production domain handling when deployed behind https.
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        session_cookie(&session_token, 86400)
            .parse()
            .map_err(|_| AppError::Internal(anyhow::anyhow!("failed to build cookie")))?,
    );

    // 202 Accepted: the password half of sign-in succeeded. Accounts with
    // 2FA must still answer the challenge before the session is usable.
    let (status, message) = if totp_enabled {
        (
            StatusCode::ACCEPTED,
            "Password accepted — enter your two-factor code".to_string(),
        )
    } else {
        (StatusCode::OK, "Login successful".to_string())
    };

    Ok((
        status,
        headers,
        Json(AuthResponse {
            user_id,
            email,
            role,
            message,
            two_factor_required: totp_enabled,
        }),
    ))
}

pub async fn logout(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<(StatusCode, HeaderMap, Json<serde_json::Value>), AppError> {
    sqlx::query("UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(auth_user.user_id)
        .execute(&state.pool)
        .await?;

    secure_vault_audit::log_event(&state.pool, auth_user.user_id, "LOGOUT", None).await?;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        session_cookie("", 0)
            .parse()
            .map_err(|_| AppError::Internal(anyhow::anyhow!("failed to build cookie")))?,
    );

    Ok((
        StatusCode::OK,
        headers,
        Json(serde_json::json!({ "message": "Logged out" })),
    ))
}

pub async fn me(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<Json<MeResponse>, AppError> {
    let row = sqlx::query("SELECT email, role, totp_enabled FROM users WHERE id = $1")
        .bind(auth_user.user_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;

    let email: String = row.try_get("email").map_err(|_| AppError::NotFound)?;
    let role: String = row.try_get("role").map_err(|_| AppError::NotFound)?;
    let totp_enabled: bool = row.try_get("totp_enabled").map_err(|_| AppError::NotFound)?;

    Ok(Json(MeResponse {
        user_id: auth_user.user_id,
        email,
        role,
        totp_enabled,
    }))
}

pub async fn refresh(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<Json<MeResponse>, AppError> {
    let row = sqlx::query("SELECT email, role, totp_enabled FROM users WHERE id = $1")
        .bind(auth_user.user_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;

    let email: String = row.try_get("email").map_err(|_| AppError::NotFound)?;
    let role: String = row.try_get("role").map_err(|_| AppError::NotFound)?;
    let totp_enabled: bool = row.try_get("totp_enabled").map_err(|_| AppError::NotFound)?;

    Ok(Json(MeResponse {
        user_id: auth_user.user_id,
        email,
        role,
        totp_enabled,
    }))
}

// ---------------------------------------------------------------------------
// TOTP two-factor authentication (RFC 6238)
// ---------------------------------------------------------------------------

use serde_json::json;

#[derive(Deserialize)]
pub struct TwoFactorCodeRequest {
    pub code: String,
}

#[derive(Deserialize)]
pub struct Disable2faRequest {
    pub code: String,
    /// Re-entering the account password makes disabling 2FA a two-factor
    /// action (something you have + something you know).
    pub password: String,
}

/// POST /auth/2fa/setup — begin enrollment: generate a secret, store it in
/// the *pending* column, and return the otpauth URI (the client renders it
/// as a QR code) plus the raw secret (for manual entry).
pub async fn start_2fa_setup(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<Json<serde_json::Value>, AppError> {
    if totp_enabled(&state, auth_user.user_id).await? {
        return Err(AppError::Conflict(
            "Two-factor authentication is already enabled — disable it first".into(),
        ));
    }

    let secret = secure_vault_crypto::totp::generate_totp_secret();
    sqlx::query("UPDATE users SET totp_pending_secret = $2, updated_at = NOW() WHERE id = $1")
        .bind(auth_user.user_id)
        .bind(&secret)
        .execute(&state.pool)
        .await?;

    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(auth_user.user_id)
        .fetch_one(&state.pool)
        .await?;

    let uri = secure_vault_crypto::totp::totp_uri(&secret, &email, "SecureVault");
    secure_vault_audit::log_event(&state.pool, auth_user.user_id, "TWO_FACTOR_SETUP_STARTED", None)
        .await?;

    Ok(Json(json!({ "secret": secret, "otpauth_uri": uri })))
}

/// POST /auth/2fa/verify — confirm a code from the authenticator app against
/// the pending secret; on success 2FA is active for the account.
pub async fn verify_2fa(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(req): Json<TwoFactorCodeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row = sqlx::query("SELECT email, totp_pending_secret, totp_enabled FROM users WHERE id = $1")
        .bind(auth_user.user_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;

    let email: String = row.try_get("email").map_err(|_| AppError::NotFound)?;
    let pending: Option<String> = row
        .try_get("totp_pending_secret")
        .map_err(|_| AppError::NotFound)?;
    let enabled: bool = row.try_get("totp_enabled").map_err(|_| AppError::NotFound)?;

    let Some(secret) = pending.filter(|s| !s.is_empty()) else {
        return Err(AppError::Validation(
            "No two-factor setup in progress — start setup first".into(),
        ));
    };
    if enabled {
        return Err(AppError::Conflict("Two-factor is already enabled".into()));
    }

    let now = chrono::Utc::now().timestamp() as u64;
    if !secure_vault_crypto::totp::verify_totp(&secret, &req.code, now, 1) {
        return Err(AppError::Validation(
            "That code is not valid yet — check your authenticator app and try again".into(),
        ));
    }

    sqlx::query(
        "UPDATE users SET totp_enabled = TRUE, totp_secret = $2, totp_pending_secret = NULL, updated_at = NOW() WHERE id = $1",
    )
    .bind(auth_user.user_id)
    .bind(&secret)
    .execute(&state.pool)
    .await?;

    secure_vault_audit::log_event_with_meta(
        &state.pool,
        auth_user.user_id,
        "TWO_FACTOR_ENABLED",
        None,
        Some(json!({ "target_user": email })),
    )
    .await?;

    Ok(Json(json!({ "enabled": true, "message": "Two-factor authentication is now active" })))
}

/// POST /auth/2fa/disable — require a valid current code AND the account
/// password, then clear the stored secret.
pub async fn disable_2fa(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(req): Json<Disable2faRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row = sqlx::query("SELECT email, totp_secret, totp_enabled, password_hash FROM users WHERE id = $1")
        .bind(auth_user.user_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;

    let email: String = row.try_get("email").map_err(|_| AppError::NotFound)?;
    let secret: Option<String> = row.try_get("totp_secret").map_err(|_| AppError::NotFound)?;
    let enabled: bool = row.try_get("totp_enabled").map_err(|_| AppError::NotFound)?;
    let password_hash: Option<String> = row
        .try_get("password_hash")
        .map_err(|_| AppError::NotFound)?;

    if !enabled {
        return Err(AppError::Validation("Two-factor is not enabled".into()));
    }
    let Some(secret) = secret else {
        return Err(AppError::Internal(anyhow::anyhow!(
            "2FA enabled but no secret stored for user {email}"
        )));
    };

    let now = chrono::Utc::now().timestamp() as u64;
    if !secure_vault_crypto::totp::verify_totp(&secret, &req.code, now, 1) {
        return Err(AppError::Validation("Invalid two-factor code".into()));
    }

    let password_ok = password_hash
        .and_then(|h| secure_vault_crypto::verify_password(&req.password, &h).ok())
        .unwrap_or(false);
    if !password_ok {
        return Err(AppError::Unauthorized);
    }

    sqlx::query(
        "UPDATE users SET totp_enabled = FALSE, totp_secret = NULL, totp_pending_secret = NULL, updated_at = NOW() WHERE id = $1",
    )
    .bind(auth_user.user_id)
    .execute(&state.pool)
    .await?;

    secure_vault_audit::log_event_with_meta(
        &state.pool,
        auth_user.user_id,
        "TWO_FACTOR_DISABLED",
        None,
        Some(json!({ "target_user": email })),
    )
    .await?;

    Ok(Json(json!({ "enabled": false, "message": "Two-factor authentication disabled" })))
}

/// POST /auth/2fa/challenge — complete a half-login (session created by
/// /auth/login while `awaiting_2fa`). Accepts the TOTP code, activates the
/// session, and returns the caller's identity.
pub async fn challenge_2fa(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(req): Json<TwoFactorCodeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !auth_user.awaiting_2fa {
        return Err(AppError::Validation(
            "This session is not awaiting a two-factor code".into(),
        ));
    }

    let row = sqlx::query("SELECT email, totp_secret FROM users WHERE id = $1")
        .bind(auth_user.user_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;

    let email: String = row.try_get("email").map_err(|_| AppError::NotFound)?;
    let secret: Option<String> = row.try_get("totp_secret").map_err(|_| AppError::NotFound)?;
    let Some(secret) = secret else {
        return Err(AppError::Internal(anyhow::anyhow!(
            "awaiting_2fa session but no TOTP secret for user {email}"
        )));
    };

    let now = chrono::Utc::now().timestamp() as u64;
    if !secure_vault_crypto::totp::verify_totp(&secret, &req.code, now, 1) {
        secure_vault_audit::log_event(&state.pool, auth_user.user_id, "TWO_FACTOR_CHALLENGE_FAILED", None)
            .await?;
        return Err(AppError::Unauthorized);
    }

    // Activate the session — the account is fully signed in now.
    sqlx::query("UPDATE sessions SET awaiting_2fa = FALSE WHERE token_hash = $1")
        .bind(&auth_user.token_hash)
        .execute(&state.pool)
        .await?;

    secure_vault_audit::log_event(&state.pool, auth_user.user_id, "LOGIN_SUCCESS", None).await?;

    Ok(Json(json!({
        "user_id": auth_user.user_id,
        "email": email,
        "message": "Two-factor verification complete"
    })))
}

/// Helper: is 2FA active for this user?
async fn totp_enabled(state: &AppState, user_id: Uuid) -> Result<bool, AppError> {
    let enabled: Option<bool> =
        sqlx::query_scalar("SELECT totp_enabled FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
    Ok(enabled.unwrap_or(false))
}
