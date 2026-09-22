//! Periodic maintenance: data-lifecycle enforcement that must not block
//! request handling.
//!
//! - **Session lifecycle** — rows whose `expires_at` has passed are deleted;
//!   rows revoked more than 7 days ago are dropped too (revoked token hashes
//!   are kept briefly so "who was force-signed-out" forensics stay possible).
//! - **Snapshot retention** — per user, only the newest
//!   `SNAPSHOT_RETENTION_COUNT` encrypted snapshots are kept (`0` disables
//!   pruning). Older snapshots are bulk-deleted so vault sync history cannot
//!   grow without bound; the newest snapshot is always retained, so sync and
//!   recovery are unaffected.
//!
//! Failures are logged and retried on the next tick — the loop never stops
//! the process. The retention limit is re-read every tick, so changing the
//! env var (in a redeploy) takes effect without code changes.

use sqlx::PgPool;
use std::time::Duration;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(60 * 60); // 1 hour
const REVOKED_SESSION_GRACE_DAYS: i64 = 7;

/// Delete expired/revoked sessions and prune old vault snapshots.
/// `snapshot_retention` is the per-user snapshot limit from the app config
/// (`0` disables pruning). Returns the number of rows removed per category.
pub async fn run_cleanup_once(
    pool: &PgPool,
    snapshot_retention: u32,
) -> anyhow::Result<(u64, u64)> {
    let expired = sqlx::query("DELETE FROM sessions WHERE expires_at < NOW()")
        .execute(pool)
        .await?
        .rows_affected();

    let revoked = sqlx::query(
        "DELETE FROM sessions WHERE revoked_at IS NOT NULL AND revoked_at < NOW() - ($1 || ' days')::interval",
    )
    .bind(REVOKED_SESSION_GRACE_DAYS.to_string())
    .execute(pool)
    .await?
    .rows_affected();

    let mut pruned: u64 = 0;
    if snapshot_retention > 0 {
        // Keep the newest `snapshot_retention` snapshots per user (versions
        // are strictly increasing, so version order == recency order).
        let result = sqlx::query(
            r#"
            DELETE FROM vault_snapshots s
            WHERE s.version <= (
                SELECT COALESCE(MAX(version), 0) - $1
                FROM vault_snapshots s2
                WHERE s2.user_id = s.user_id
            )
            "#,
        )
        .bind(snapshot_retention as i64)
        .execute(pool)
        .await?;
        pruned = result.rows_affected();
    }

    tracing::info!(
        expired_sessions = expired,
        revoked_sessions = revoked,
        pruned_snapshots = pruned,
        "maintenance cleanup tick"
    );
    Ok((expired + revoked, pruned))
}

/// Spawn-friendly loop: run the cleanup at boot, then every hour. The
/// retention limit is fixed at boot from the app config (change it via env
/// and restart — see SNAPSHOT_RETENTION_COUNT).
pub async fn run_cleanup_loop(pool: PgPool, snapshot_retention: u32) {
    loop {
        if let Err(e) = run_cleanup_once(&pool, snapshot_retention).await {
            tracing::error!("maintenance cleanup failed (will retry next tick): {e}");
        }
        tokio::time::sleep(CLEANUP_INTERVAL).await;
    }
}
