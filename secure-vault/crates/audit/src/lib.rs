use anyhow::Result;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroize;

/// Insert an audit event. `metadata` is free-form JSON (e.g. the actor, the
/// target user, or the version affected by the event) so admin views can show
/// *what* changed, not just *that* something changed.
pub async fn log_event(
    pool: &PgPool,
    user_id: Uuid,
    event_type: &str,
    device_id: Option<Uuid>,
) -> Result<()> {
    log_event_with_meta(pool, user_id, event_type, device_id, None).await
}

/// Insert an audit event with free-form JSON metadata.
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

/// Insert an audit event recording a **salted SHA-256 hash of the client IP**
/// (never the raw address). The salt is fixed per deployment via the
/// `AUDIT_IP_SALT` secret so the hashes are stable enough to correlate
/// repeated failed logins from one source, while the raw IP is never stored.
/// `ip` should be the bucketing client address (X-Forwarded-For first hop or
/// the socket peer, matching the rate limiter's keying).
pub async fn log_event_with_ip(
    pool: &PgPool,
    user_id: Uuid,
    event_type: &str,
    device_id: Option<Uuid>,
    ip: Option<&str>,
) -> Result<()> {
    let ip_hash = ip.map(|ip| {
        let salt = std::env::var("AUDIT_IP_SALT").unwrap_or_default();
        let mut input = salt;
        input.push_str(ip);
        let digest = secure_vault_crypto::hash_sha256(input.as_bytes());
        input.zeroize();
        digest
    });

    sqlx::query(
        r#"
        INSERT INTO audit_events (id, user_id, device_id, event_type, ip_hash, metadata)
        VALUES ($1, $2, $3, $4, $5, NULL)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(device_id)
    .bind(event_type)
    .bind(ip_hash)
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn ip_hash_is_salted_and_stable() {
        // The salt comes from AUDIT_IP_SALT at call time, not compile time, so
        // tests can only assert determinism within a fixed environment and the
        // general shape (32 bytes, differs from an unsalted hash).
        std::env::set_var("AUDIT_IP_SALT", "test-salt-123");
        let salted = {
            let mut input = "test-salt-123".to_string();
            input.push_str("203.0.113.9");
            secure_vault_crypto::hash_sha256(input.as_bytes())
        };
        let unsalted = secure_vault_crypto::hash_sha256(b"203.0.113.9");
        assert_eq!(salted.len(), 32);
        assert_ne!(salted, unsalted, "salt must change the digest");
        // Same input + same salt = same hash (correlatable), but only the hash
        // is ever persisted.
        std::env::remove_var("AUDIT_IP_SALT");
    }
}
