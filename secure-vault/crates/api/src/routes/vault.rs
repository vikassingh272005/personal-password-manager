use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::errors::AppError;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;

/// A wrapped copy of the vault encryption key (VEK). The wrap is AES-256-GCM
/// of the 32-byte VEK under a wrapping key; the server stores it but never
/// sees either key.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WrapFields {
    pub ciphertext: String,
    pub nonce: String,
}

#[derive(Deserialize)]
pub struct UpdateVaultRequest {
    pub version: i32,
    pub ciphertext: String,
    pub nonce: String,
    /// Wrapped VEK under the master-password KEK. The first PUT after
    /// registration carries it to initialize the vault; later PUTs may omit it.
    pub kek_wrap: Option<WrapFields>,
    /// Wrapped VEK under the Secret Key recovery key.
    pub recovery_wrap: Option<WrapFields>,
}

#[derive(Deserialize)]
pub struct UpdateVaultKeysRequest {
    /// New master-password wrap (after a master password change).
    pub kek_wrap: Option<WrapFields>,
    /// New recovery wrap (after generating a recovery kit).
    pub recovery_wrap: Option<WrapFields>,
}

#[derive(Serialize)]
pub struct VaultResponse {
    /// Current vault version (highest snapshot version; 1 from birth).
    pub version: i32,
    pub kdf_algorithm: String,
    pub kdf_memory: i32,
    pub kdf_iterations: i32,
    pub kdf_parallelism: i32,
    pub kdf_salt: String,
    /// Retired in favor of client-side key derivation; kept for schema
    /// compatibility. The server never reads it back.
    pub encrypted_vault_key: String,
    /// Wrapped VEK under the master-password KEK. NULL on legacy vaults whose
    /// items are still encrypted directly under the password-derived key.
    pub kek_wrap: Option<WrapFields>,
    /// Wrapped VEK under the Secret Key recovery key, if a kit was generated.
    pub recovery_wrap: Option<WrapFields>,
    /// Latest encrypted snapshot, if the client has ever synced.
    pub ciphertext: Option<String>,
    pub nonce: Option<String>,
    pub updated_at: Option<String>,
}

/// Decode + validate a wrap submitted by the client. A wrap is a 12-byte
/// AES-GCM nonce plus 48 bytes of ciphertext (32-byte key + 16-byte tag).
fn decode_wrap(wrap: &WrapFields) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let ciphertext = base64::Engine::decode(&b64, &wrap.ciphertext)
        .map_err(|_| AppError::Validation("wrap ciphertext must be base64-encoded".into()))?;
    let nonce = base64::Engine::decode(&b64, &wrap.nonce)
        .map_err(|_| AppError::Validation("wrap nonce must be base64-encoded".into()))?;
    if nonce.len() != 12 {
        return Err(AppError::Validation(
            "wrap nonce must be a 12-byte AES-GCM IV".into(),
        ));
    }
    if ciphertext.len() != 48 {
        return Err(AppError::Validation(
            "wrap ciphertext must be 48 bytes (32-byte key + GCM tag)".into(),
        ));
    }
    Ok((ciphertext, nonce))
}

pub async fn get_vault(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<Json<VaultResponse>, AppError> {
    let row = sqlx::query(
        r#"
        SELECT version, kdf_algorithm, kdf_memory, kdf_iterations, kdf_parallelism,
               kdf_salt, encrypted_vault_key, kek_wrap_ciphertext, kek_wrap_nonce,
               recovery_wrap_ciphertext, recovery_wrap_nonce, updated_at
        FROM vaults WHERE user_id = $1
        "#,
    )
    .bind(auth_user.user_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let version: i32 = row.try_get("version").map_err(|_| AppError::NotFound)?;
    let kdf_algorithm: String = row
        .try_get("kdf_algorithm")
        .map_err(|_| AppError::NotFound)?;
    let kdf_memory: i32 = row.try_get("kdf_memory").map_err(|_| AppError::NotFound)?;
    let kdf_iterations: i32 = row
        .try_get("kdf_iterations")
        .map_err(|_| AppError::NotFound)?;
    let kdf_parallelism: i32 = row
        .try_get("kdf_parallelism")
        .map_err(|_| AppError::NotFound)?;
    let kdf_salt: Vec<u8> = row.try_get("kdf_salt").map_err(|_| AppError::NotFound)?;
    let encrypted_vault_key: Vec<u8> = row
        .try_get("encrypted_vault_key")
        .map_err(|_| AppError::NotFound)?;
    let vault_updated_at: chrono::DateTime<chrono::Utc> =
        row.try_get("updated_at").map_err(|_| AppError::NotFound)?;

    // Latest snapshot, if one exists yet (a freshly registered vault has none).
    let snapshot = sqlx::query(
        r#"
        SELECT version, ciphertext, nonce, created_at
        FROM vault_snapshots
        WHERE user_id = $1
        ORDER BY version DESC
        LIMIT 1
        "#,
    )
    .bind(auth_user.user_id)
    .fetch_optional(&state.pool)
    .await?;

    let (ciphertext, nonce, updated_at) = match snapshot {
        Some(snap) => {
            let snap_ciphertext: Vec<u8> = snap.try_get("ciphertext")?;
            let snap_nonce: Option<Vec<u8>> = snap.try_get("nonce")?;
            let snap_created: chrono::DateTime<chrono::Utc> = snap.try_get("created_at")?;
            (
                Some(snap_ciphertext),
                snap_nonce,
                Some(snap_created.to_rfc3339()),
            )
        }
        None => (None, None, Some(vault_updated_at.to_rfc3339())),
    };

    let kek_wrap_ciphertext: Option<Vec<u8>> = row.try_get("kek_wrap_ciphertext")?;
    let kek_wrap_nonce: Option<Vec<u8>> = row.try_get("kek_wrap_nonce")?;
    let recovery_wrap_ciphertext: Option<Vec<u8>> = row.try_get("recovery_wrap_ciphertext")?;
    let recovery_wrap_nonce: Option<Vec<u8>> = row.try_get("recovery_wrap_nonce")?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let to_wrap = |ciphertext: Option<Vec<u8>>, nonce: Option<Vec<u8>>| match (ciphertext, nonce) {
        (Some(ct), Some(n)) => Some(WrapFields {
            ciphertext: base64::Engine::encode(&b64, ct),
            nonce: base64::Engine::encode(&b64, n),
        }),
        _ => None,
    };

    Ok(Json(VaultResponse {
        version,
        kdf_algorithm,
        kdf_memory,
        kdf_iterations,
        kdf_parallelism,
        kdf_salt: base64::Engine::encode(&b64, &kdf_salt),
        encrypted_vault_key: base64::Engine::encode(&b64, &encrypted_vault_key),
        kek_wrap: to_wrap(kek_wrap_ciphertext, kek_wrap_nonce),
        recovery_wrap: to_wrap(recovery_wrap_ciphertext, recovery_wrap_nonce),
        ciphertext: ciphertext.map(|ct| base64::Engine::encode(&b64, ct)),
        nonce: nonce.map(|n| base64::Engine::encode(&b64, n)),
        updated_at,
    }))
}

/// Validate a wrap payload and store it on the vaults row. Returns the bytes
/// for the audit log (or None when the field was absent).
async fn apply_wrap_update(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    column: &str,
    wrap: &Option<WrapFields>,
) -> Result<Option<usize>, AppError> {
    let Some(wrap) = wrap else {
        return Ok(None);
    };
    let (ciphertext, nonce) = decode_wrap(wrap)?;
    let sql = format!(
        "UPDATE vaults SET {column}_ciphertext = $2, {column}_nonce = $3, updated_at = NOW() \
         WHERE user_id = $1"
    );
    sqlx::query(&sql)
        .bind(user_id)
        .bind(&ciphertext)
        .bind(&nonce)
        .execute(&mut **tx)
        .await?;
    Ok(Some(ciphertext.len()))
}

pub async fn update_vault(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(req): Json<UpdateVaultRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let ciphertext = base64::Engine::decode(&b64, &req.ciphertext)
        .map_err(|_| AppError::Validation("ciphertext must be base64-encoded".into()))?;
    let nonce = base64::Engine::decode(&b64, &req.nonce)
        .map_err(|_| AppError::Validation("nonce must be base64-encoded".into()))?;
    if nonce.len() != 12 {
        return Err(AppError::Validation(
            "nonce must be a 12-byte AES-GCM IV".into(),
        ));
    }

    let mut tx = state.pool.begin().await?;

    // Lock the user's vaults row so the version check below is atomic: without
    // it, two devices pushing the same version can both read MAX(version)
    // before either inserts, and both land the same snapshot version.
    let vault_exists: Option<i32> =
        sqlx::query_scalar("SELECT version FROM vaults WHERE user_id = $1 FOR UPDATE")
            .bind(auth_user.user_id)
            .fetch_optional(&mut *tx)
            .await?;
    if vault_exists.is_none() {
        return Err(AppError::NotFound);
    }

    // The version a client sends must be exactly one past the newest stored
    // snapshot. A fresh vault (no snapshots yet) accepts version 1.
    let max_version: Option<i32> =
        sqlx::query_scalar("SELECT MAX(version) FROM vault_snapshots WHERE user_id = $1")
            .bind(auth_user.user_id)
            .fetch_one(&mut *tx)
            .await?;

    let expected = max_version.unwrap_or(0) + 1;
    if req.version != expected {
        return Err(AppError::Conflict(format!(
            "Vault version conflict - expected version {expected}, got {} (a newer version exists)",
            req.version
        )));
    }

    sqlx::query("UPDATE vaults SET version = $2, updated_at = NOW() WHERE user_id = $1")
        .bind(auth_user.user_id)
        .bind(req.version)
        .execute(&mut *tx)
        .await?;

    // Persist the snapshot (with its nonce) so sync history is observable and
    // the blob can be decrypted again later.
    // Persist the snapshot (with its nonce) so sync history is observable and
    // the blob can be decrypted again later.
    sqlx::query(
        r#"
        INSERT INTO vault_snapshots (id, user_id, version, blob_size, ciphertext, nonce)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(auth_user.user_id)
    .bind(req.version)
    .bind(ciphertext.len() as i32)
    .bind(&ciphertext)
    .bind(&nonce)
    .execute(&mut *tx)
    .await?;

    // The first PUT initializes the key hierarchy (wrapped VEK). Later PUTs
    // (item syncs) normally omit the wraps; if present they are refreshed
    // atomically with the snapshot.
    let kek_bytes =
        apply_wrap_update(&mut tx, auth_user.user_id, "kek_wrap", &req.kek_wrap).await?;
    let recovery_bytes = apply_wrap_update(
        &mut tx,
        auth_user.user_id,
        "recovery_wrap",
        &req.recovery_wrap,
    )
    .await?;

    tx.commit().await?;

    let mut meta = serde_json::json!({
        "version": req.version,
        "blob_bytes": ciphertext.len()
    });
    if kek_bytes.is_some() {
        meta["kek_wrap_bytes"] = serde_json::json!(kek_bytes);
    }
    if recovery_bytes.is_some() {
        meta["recovery_wrap_bytes"] = serde_json::json!(recovery_bytes);
    }

    secure_vault_audit::log_event_with_meta(
        &state.pool,
        auth_user.user_id,
        "VAULT_UPDATED",
        None,
        Some(meta),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "message": "Vault updated",
        "version": req.version
    })))
}

/// Rewrap the vault key without touching the encrypted snapshot or bumping the
/// version. Used by the master-password change (new KEK wrap) and recovery-kit
/// generation (new recovery wrap). Requires an authenticated session; the
/// client proves knowledge of the old master password by unwrapping the VEK
/// locally before submitting.
pub async fn update_vault_keys(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(req): Json<UpdateVaultKeysRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if req.kek_wrap.is_none() && req.recovery_wrap.is_none() {
        return Err(AppError::Validation(
            "provide at least one wrap to update".into(),
        ));
    }

    let mut tx = state.pool.begin().await?;

    let vault_exists: Option<i32> =
        sqlx::query_scalar("SELECT version FROM vaults WHERE user_id = $1 FOR UPDATE")
            .bind(auth_user.user_id)
            .fetch_optional(&mut *tx)
            .await?;
    if vault_exists.is_none() {
        return Err(AppError::NotFound);
    }

    let kek_bytes =
        apply_wrap_update(&mut tx, auth_user.user_id, "kek_wrap", &req.kek_wrap).await?;
    let recovery_bytes = apply_wrap_update(
        &mut tx,
        auth_user.user_id,
        "recovery_wrap",
        &req.recovery_wrap,
    )
    .await?;

    tx.commit().await?;

    let event = if req.kek_wrap.is_some() {
        "MASTER_PASSWORD_CHANGED"
    } else {
        "RECOVERY_KEY_GENERATED"
    };
    secure_vault_audit::log_event_with_meta(
        &state.pool,
        auth_user.user_id,
        event,
        None,
        Some(serde_json::json!({
            "kek_wrap_bytes": kek_bytes,
            "recovery_wrap_bytes": recovery_bytes
        })),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "message": "Vault keys updated",
        "kek_wrap_bytes": kek_bytes,
        "recovery_wrap_bytes": recovery_bytes
    })))
}
