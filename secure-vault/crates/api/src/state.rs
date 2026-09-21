use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use secure_vault_config::AppConfig;

use crate::middleware::rate_limit::RateLimiter;

/// One issued WebAuthn challenge. Challenges are single-use, bound to the
/// ceremony that requested them, and expire quickly.
#[derive(Clone, Debug)]
pub struct PendingChallenge {
    pub challenge: String,
    /// For login ceremonies: the email the user asked to sign in as (`None`
    /// means discoverable-credential / usernameless sign-in).
    pub email: Option<String>,
    pub created_at: std::time::Instant,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: AppConfig,
    /// Sliding-window limiters for the public auth endpoints, keyed by client
    /// IP. In-memory and per-process (single-instance deployment model).
    pub login_limiter: Arc<RateLimiter>,
    pub register_limiter: Arc<RateLimiter>,
    /// Live WebAuthn challenges (registration + assertion ceremonies).
    pub passkey_challenges: Arc<Mutex<HashMap<String, PendingChallenge>>>,
}

impl AppState {
    pub fn new(pool: PgPool, config: AppConfig) -> Self {
        Self {
            pool,
            config,
            login_limiter: Arc::new(RateLimiter::new(10, std::time::Duration::from_secs(60))),
            register_limiter: Arc::new(RateLimiter::new(5, std::time::Duration::from_secs(300))),
            passkey_challenges: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Store a fresh challenge and return its id. Expired entries are reaped
    /// on every insert, so the map cannot grow unbounded.
    pub fn insert_passkey_challenge(&self, email: Option<String>, challenge: String) -> String {
        let id = secure_vault_crypto::generate_random_string(32);
        let mut map = self
            .passkey_challenges
            .lock()
            .expect("passkey challenge map poisoned");
        map.retain(|_, c| c.created_at.elapsed() < std::time::Duration::from_secs(300));
        map.insert(
            id.clone(),
            PendingChallenge {
                challenge,
                email,
                created_at: std::time::Instant::now(),
            },
        );
        id
    }

    /// Take a challenge out of the store (single-use). Returns `None` when the
    /// id is unknown or expired.
    pub fn take_passkey_challenge(&self, id: &str) -> Option<PendingChallenge> {
        let mut map = self
            .passkey_challenges
            .lock()
            .expect("passkey challenge map poisoned");
        map.remove(id)
            .filter(|c| c.created_at.elapsed() < std::time::Duration::from_secs(300))
    }
}
