// Admin console endpoints. Everything here is gated by `require_admin`, which
// resolves the session and verifies the caller's role is `admin` on every
// request. Admin actions are themselves written to the audit log so the
// console can be audited.
//
// Zero-knowledge note: vault *content* is never visible server-side. These
// endpoints surface accounts, devices, sessions, vault sync activity (sizes /
// versions only) and the audit trail — not decrypted credentials.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, Row};
use uuid::Uuid;

use crate::errors::AppError;
use crate::middleware::auth::{ensure_admin, AuthenticatedUser};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// GET /api/v1/admin/overview
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct OverviewResponse {
    pub totals: serde_json::Map<String, Value>,
    pub recent_events: Vec<AuditEventRow>,
}

pub async fn overview(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<Json<OverviewResponse>, AppError> {
    ensure_admin(&auth_user)?;

    let row = sqlx::query(
        r#"
        SELECT
            (SELECT COUNT(*)::int FROM users) AS users,
            (SELECT COUNT(*)::int FROM users WHERE role = 'admin') AS admins,
            (SELECT COUNT(*)::int FROM sessions WHERE revoked_at IS NULL AND expires_at > NOW()) AS active_sessions,
            (SELECT COUNT(*)::int FROM devices WHERE revoked_at IS NULL) AS active_devices,
            (SELECT COUNT(*)::int FROM vault_snapshots) AS vault_syncs,
            (SELECT COUNT(*)::int FROM audit_events WHERE created_at > NOW() - INTERVAL '24 hours') AS events_24h,
            (SELECT COUNT(*)::int FROM audit_events) AS events_total,
            (SELECT COUNT(*)::int FROM users WHERE created_at > NOW() - INTERVAL '24 hours') AS signups_24h
        "#,
    )
    .fetch_one(&state.pool)
    .await?;

    let mut totals = serde_json::Map::new();
    for key in [
        "users",
        "admins",
        "active_sessions",
        "active_devices",
        "vault_syncs",
        "events_24h",
        "events_total",
        "signups_24h",
    ] {
        totals.insert(
            key.to_string(),
            serde_json::json!(row.try_get::<i32, _>(key).unwrap_or(0)),
        );
    }

    let events = recent_events(&state).await?;

    // Note: views are deliberately NOT audit-logged. Logging reads would
    // pollute the feed with "ADMIN_*_VIEWED" rows every time the console is
    // opened — only actions (role changes, revocations) are recorded.
    Ok(Json(OverviewResponse {
        totals,
        recent_events: events,
    }))
}

async fn recent_events(state: &AppState) -> Result<Vec<AuditEventRow>, AppError> {
    let rows = sqlx::query_as::<_, AuditEventRow>(
        r#"
        SELECT a.id::text AS id, u.email AS email, a.event_type AS event_type,
               a.created_at::timestamptz AS created_at, a.metadata AS metadata
        FROM audit_events a
        JOIN users u ON u.id = a.user_id
        ORDER BY a.created_at DESC
        LIMIT 15
        "#,
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// GET /api/v1/admin/users
// ---------------------------------------------------------------------------

#[derive(Serialize, FromRow)]
pub struct AdminUser {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_active_at: Option<chrono::DateTime<chrono::Utc>>,
    pub device_count: i32,
    pub session_count: i32,
    pub sync_count: i32,
    pub vault_version: Option<i32>,
    pub vault_updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub two_factor_enabled: bool,
}

pub async fn list_users(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<Json<Vec<AdminUser>>, AppError> {
    ensure_admin(&auth_user)?;

    let users = sqlx::query_as::<_, AdminUser>(
        r#"
        SELECT u.id, u.email, u.role,
               u.created_at::timestamptz AS created_at,
               (SELECT MAX(a.created_at)::timestamptz FROM audit_events a WHERE a.user_id = u.id) AS last_active_at,
               (SELECT COUNT(*)::int FROM devices d WHERE d.user_id = u.id AND d.revoked_at IS NULL) AS device_count,
               (SELECT COUNT(*)::int FROM sessions s WHERE s.user_id = u.id AND s.revoked_at IS NULL AND s.expires_at > NOW()) AS session_count,
               (SELECT COUNT(*)::int FROM vault_snapshots vs WHERE vs.user_id = u.id) AS sync_count,
               v.version AS vault_version,
               v.updated_at::timestamptz AS vault_updated_at,
               u.totp_enabled AS two_factor_enabled
        FROM users u
        LEFT JOIN vaults v ON v.user_id = u.id
        ORDER BY u.created_at DESC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    // Views are deliberately not audit-logged — see overview().
    Ok(Json(users))
}

// ---------------------------------------------------------------------------
// PATCH /api/v1/admin/users/{user_id}/role
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SetRoleRequest {
    pub role: String,
}

#[derive(Serialize)]
pub struct RoleResponse {
    pub user_id: Uuid,
    pub email: String,
    pub role: String,
    pub message: String,
}

pub async fn set_role(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Path(user_id): Path<Uuid>,
    Json(req): Json<SetRoleRequest>,
) -> Result<(StatusCode, Json<RoleResponse>), AppError> {
    ensure_admin(&auth_user)?;

    let new_role = req.role.trim().to_lowercase();
    if new_role != "user" && new_role != "admin" {
        return Err(AppError::Validation(
            "role must be 'user' or 'admin'".into(),
        ));
    }

    if auth_user.user_id == user_id {
        return Err(AppError::Validation(
            "Admins cannot change their own role — have another admin do it, or set ADMIN_EMAILS"
                .into(),
        ));
    }

    let row = sqlx::query("SELECT email, role FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;

    let email: String = row.try_get("email").map_err(|_| AppError::NotFound)?;
    let current_role: String = row.try_get("role").map_err(|_| AppError::NotFound)?;

    if current_role == new_role {
        return Ok((
            StatusCode::OK,
            Json(RoleResponse {
                user_id,
                email,
                role: new_role,
                message: "Role unchanged".into(),
            }),
        ));
    }

    // Never leave the system without an admin.
    if current_role == "admin" && new_role == "user" {
        let admins: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            .fetch_one(&state.pool)
            .await?;
        if admins <= 1 {
            return Err(AppError::Conflict("Cannot demote the last admin".into()));
        }
    }

    sqlx::query("UPDATE users SET role = $2, updated_at = NOW() WHERE id = $1")
        .bind(user_id)
        .bind(&new_role)
        .execute(&state.pool)
        .await?;

    secure_vault_audit::log_event_with_meta(
        &state.pool,
        auth_user.user_id,
        "ADMIN_ROLE_CHANGED",
        None,
        Some(serde_json::json!({
            "target_user": email,
            "target_user_id": user_id,
            "previous_role": current_role,
            "new_role": new_role.clone()
        })),
    )
    .await?;

    Ok((
        StatusCode::OK,
        Json(RoleResponse {
            user_id,
            email,
            role: new_role.clone(),
            message: format!("Role changed from {current_role} to {new_role}"),
        }),
    ))
}

// ---------------------------------------------------------------------------
// POST /api/v1/admin/users/{user_id}/revoke-sessions
// ---------------------------------------------------------------------------

pub async fn revoke_sessions(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Path(user_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    ensure_admin(&auth_user)?;

    let row = sqlx::query("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;
    let email: String = row.try_get("email").map_err(|_| AppError::NotFound)?;

    let result = sqlx::query(
        "UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(&state.pool)
    .await?;

    secure_vault_audit::log_event_with_meta(
        &state.pool,
        auth_user.user_id,
        "ADMIN_SESSIONS_REVOKED",
        None,
        Some(serde_json::json!({
            "target_user": email,
            "target_user_id": user_id,
            "revoked_count": result.rows_affected()
        })),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "message": format!("Revoked {} session(s) for {email}", result.rows_affected())
    })))
}

// ---------------------------------------------------------------------------
// GET /api/v1/admin/audit
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AuditQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub event_type: Option<String>,
    pub user_id: Option<Uuid>,
}

#[derive(Serialize, FromRow, Clone)]
pub struct AuditEventRow {
    pub id: String,
    pub email: String,
    pub event_type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub metadata: Option<Value>,
}

#[derive(Serialize)]
pub struct AuditListResponse {
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
    pub events: Vec<AuditEventRow>,
}

pub async fn list_audit(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditListResponse>, AppError> {
    ensure_admin(&auth_user)?;

    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);

    let total: i64 = {
        let mut qb = sqlx::QueryBuilder::new(
            "SELECT COUNT(*) FROM audit_events a JOIN users u ON u.id = a.user_id WHERE 1=1",
        );
        if let Some(event_type) = &query.event_type {
            qb.push(" AND a.event_type = ").push_bind(event_type);
        }
        if let Some(user_id) = &query.user_id {
            qb.push(" AND a.user_id = ").push_bind(user_id);
        }
        qb.build_query_scalar().fetch_one(&state.pool).await?
    };

    let events: Vec<AuditEventRow> = {
        let mut qb = sqlx::QueryBuilder::new(
            "SELECT a.id::text AS id, u.email AS email, a.event_type AS event_type, \
             a.created_at::timestamptz AS created_at, a.metadata AS metadata \
             FROM audit_events a JOIN users u ON u.id = a.user_id WHERE 1=1",
        );
        if let Some(event_type) = &query.event_type {
            qb.push(" AND a.event_type = ").push_bind(event_type);
        }
        if let Some(user_id) = &query.user_id {
            qb.push(" AND a.user_id = ").push_bind(user_id);
        }
        qb.push(" ORDER BY a.created_at DESC LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        qb.build_query_as::<AuditEventRow>()
            .fetch_all(&state.pool)
            .await?
    };

    Ok(Json(AuditListResponse {
        total,
        limit,
        offset,
        events,
    }))
}
