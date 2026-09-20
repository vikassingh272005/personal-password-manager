use anyhow::Result;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

pub async fn log_event(
    pool: &PgPool,
    user_id: Uuid,
    event_type: &str,
    device_id: Option<Uuid>,
) -> Result<()> {
    log_event_with_meta(pool, user_id, event_type, device_id, None).await
}

/// Insert an audit event. `metadata` is free-form JSON (e.g. the actor, the
/// target user, or the version affected by the event) so admin views can show
/// *what* changed, not just *that* something changed.
pub async fn log_event_with_meta(
    pool: &PgPool,
    user_id: Uuid,
    event_type: &str,
    device_id: Option<Uuid>,
    metadata: Option<Value>,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO audit_events (id, user_id, device_id, event_type, metadata)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(device_id)
    .bind(event_type)
    .bind(metadata)
    .execute(pool)
    .await?;

    Ok(())
}
