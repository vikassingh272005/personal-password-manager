use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use sqlx::Row;
use uuid::Uuid;

use async_trait::async_trait;

use crate::errors::AppError;
use crate::state::AppState;

/// Authenticated, non-revoked session user, resolved from the `session_token`
/// cookie on every request. Implemented as a stateful extractor (rather than
/// a middleware layer) so protected handlers can simply take
/// `auth_user: AuthenticatedUser` and the role is always read fresh from the
/// users table — role changes and session revocations take effect immediately.
#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub role: String,
    /// True while the session has passed the password check but not yet the
    /// TOTP challenge (accounts with 2FA enabled). Such sessions may only
    /// reach the 2FA endpoints; everything else 401s.
    pub awaiting_2fa: bool,
    /// SHA-256 of the session token — lets handlers flip
    /// `awaiting_2fa` off on this exact session after a successful challenge.
    pub token_hash: Vec<u8>,
}

impl AuthenticatedUser {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

fn extract_session_token(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookie_str| {
            cookie_str
                .split(';')
                .find(|c| c.trim().starts_with("session_token="))
                .map(|c| c.trim().trim_start_matches("session_token=").to_string())
        })
}

#[async_trait]
impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_session_token(parts).ok_or(AppError::Unauthorized)?;

        let token_hash = secure_vault_crypto::hash_sha256(token.as_bytes());

        let row = sqlx::query(
            r#"
            SELECT s.user_id, s.expires_at::timestamptz, s.revoked_at::timestamptz,
                   s.awaiting_2fa, u.role
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = $1
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::Unauthorized)?;

        let user_id: Uuid = row.try_get("user_id").map_err(|_| AppError::Unauthorized)?;
        let expires_at: chrono::DateTime<chrono::Utc> = row
            .try_get("expires_at")
            .map_err(|_| AppError::Unauthorized)?;
        let revoked_at: Option<chrono::DateTime<chrono::Utc>> = row
            .try_get("revoked_at")
            .map_err(|_| AppError::Unauthorized)?;
        let awaiting_2fa: bool = row
            .try_get("awaiting_2fa")
            .map_err(|_| AppError::Unauthorized)?;
        let role: String = row.try_get("role").map_err(|_| AppError::Unauthorized)?;

        if revoked_at.is_some() {
            return Err(AppError::Unauthorized);
        }

        if expires_at < chrono::Utc::now() {
            return Err(AppError::Unauthorized);
        }

        // Half-login: only the 2FA challenge (and identity) endpoints may
        // proceed so the client can complete sign-in.
        if awaiting_2fa && parts.uri.path() != "/api/v1/auth/2fa/challenge" {
            return Err(AppError::Unauthorized);
        }

        Ok(AuthenticatedUser {
            user_id,
            role,
            awaiting_2fa,
            token_hash,
        })
    }
}

/// Role guard for the /admin routes. Callers already resolved their identity
/// via the `AuthenticatedUser` extractor; this just enforces the admin role.
pub fn ensure_admin(auth_user: &AuthenticatedUser) -> Result<(), AppError> {
    if auth_user.is_admin() {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}
