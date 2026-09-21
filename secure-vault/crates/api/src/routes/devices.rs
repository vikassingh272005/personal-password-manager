use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::errors::AppError;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct RegisterDeviceRequest {
    pub name: String,
    pub device_type: Option<String>,
}

#[derive(Serialize)]
pub struct DeviceResponse {
    pub id: Uuid,
    pub name: String,
    pub device_type: Option<String>,
    pub last_seen_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub is_current: bool,
}

pub async fn list_devices(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<Json<Vec<DeviceResponse>>, AppError> {
    let rows = sqlx::query(
        r#"
        SELECT id::text, name, device_type, last_seen_at::timestamptz,
               created_at::timestamptz, revoked_at::timestamptz
        FROM devices WHERE user_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(auth_user.user_id)
    .fetch_all(&state.pool)
    .await?;

    let devices: Vec<DeviceResponse> = rows
        .into_iter()
        .map(|row| {
            let id: Uuid = row.try_get("id").unwrap_or_default();
            let name: String = row.try_get("name").unwrap_or_default();
            let device_type: Option<String> = row.try_get("device_type").ok().flatten();
            let last_seen_at: Option<chrono::DateTime<chrono::Utc>> =
                row.try_get("last_seen_at").ok().flatten();
            let created_at: chrono::DateTime<chrono::Utc> = row
                .try_get("created_at")
                .unwrap_or_else(|_| chrono::Utc::now());
            DeviceResponse {
                id,
                name,
                device_type,
                last_seen_at,
                created_at,
                is_current: false,
            }
        })
        .collect();

    Ok(Json(devices))
}

pub async fn register_device(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<(axum::http::StatusCode, Json<DeviceResponse>), AppError> {
    let device_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO devices (id, user_id, name, device_type)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(device_id)
    .bind(auth_user.user_id)
    .bind(&req.name)
    .bind(&req.device_type)
    .execute(&state.pool)
    .await?;

    secure_vault_audit::log_event(&state.pool, auth_user.user_id, "DEVICE_ADDED", None).await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(DeviceResponse {
            id: device_id,
            name: req.name,
            device_type: req.device_type,
            last_seen_at: None,
            created_at: chrono::Utc::now(),
            is_current: false,
        }),
    ))
}

pub async fn revoke_device(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Path(device_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let _exists = sqlx::query("SELECT id FROM devices WHERE id = $1 AND user_id = $2")
        .bind(device_id)
        .bind(auth_user.user_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;

    sqlx::query("UPDATE devices SET revoked_at = NOW() WHERE id = $1")
        .bind(device_id)
        .execute(&state.pool)
        .await?;

    sqlx::query(
        "UPDATE sessions SET revoked_at = NOW() WHERE device_id = $1 AND revoked_at IS NULL",
    )
    .bind(device_id)
    .execute(&state.pool)
    .await?;

    secure_vault_audit::log_event(&state.pool, auth_user.user_id, "DEVICE_REVOKED", None).await?;

    Ok(Json(serde_json::json!({ "message": "Device revoked" })))
}
