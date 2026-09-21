use sqlx::PgPool;
use std::sync::Arc;

use secure_vault_config::AppConfig;

use crate::middleware::rate_limit::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: AppConfig,
    /// Sliding-window limiters for the public auth endpoints, keyed by client
    /// IP. In-memory and per-process (single-instance deployment model).
    pub login_limiter: Arc<RateLimiter>,
    pub register_limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn new(pool: PgPool, config: AppConfig) -> Self {
        Self {
            pool,
            config,
            login_limiter: Arc::new(RateLimiter::new(10, std::time::Duration::from_secs(60))),
            register_limiter: Arc::new(RateLimiter::new(5, std::time::Duration::from_secs(300))),
        }
    }
}
