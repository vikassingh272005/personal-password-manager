use axum::extract::connect_info::ConnectInfo;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Fixed-window rate limiter keyed by arbitrary strings (client IPs).
///
/// In-memory by design: the current deployment model is a single API process.
/// A multi-instance deployment should move these counters into Redis (the
/// compose file already ships a Redis container for that purpose).
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<RwLock<HashMap<String, (u32, Instant)>>>,
    max_requests: u32,
    window: Duration,
}

/// What `check` decided about one request.
pub enum RateDecision {
    Allowed,
    Limited,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    /// Count one request for `key` and say whether it may proceed. Expired
    /// windows reset on the next request.
    pub async fn check(&self, key: &str) -> RateDecision {
        let mut map = self.inner.write().await;
        let now = Instant::now();

        let entry = map.entry(key.to_string()).or_insert((0, now));

        if now.duration_since(entry.1) > self.window {
            *entry = (1, now);
            return RateDecision::Allowed;
        }

        if entry.0 >= self.max_requests {
            return RateDecision::Limited;
        }

        entry.0 += 1;
        RateDecision::Allowed
    }
}

fn too_many() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(serde_json::json!({
            "error": "Too many attempts — slow down and try again shortly."
        })),
    )
        .into_response()
}

/// Best-effort client IP for rate-limit keying. Behind the Next.js dev proxy
/// the socket peer is 127.0.0.1, so an `X-Forwarded-For` value (set by the
/// proxy) takes precedence when present. The header is only trusted as a
/// *bucketing* key — never for authorization — so spoofing it just moves the
/// client into a different bucket.
///
/// `ConnectInfo` is read from the request *extensions* (inserted by
/// `into_make_service_with_connect_info` before any middleware runs) rather
/// than as an extractor: axum 0.7 has no optional-extractor support, and the
/// extension is always present in production while staying absent in
/// `tower::ServiceExt::oneshot` tests.
fn client_ip_key(req: &Request<axum::body::Body>) -> String {
    if let Some(xff) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        let first = xff.split(',').next().unwrap_or("").trim();
        if !first.is_empty() {
            return first.to_string();
        }
    }
    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        return addr.ip().to_string();
    }
    "unknown".to_string()
}

/// Best-effort client-IP *label* for audit hashing, with the same precedence
/// as `client_ip_key`: X-Forwarded-For first hop when present, else the socket
/// peer. Only the salted SHA-256 of this value is ever persisted (see
/// `secure_vault_audit::log_event_with_ip`).
pub fn client_ip_for_audit(peer: Option<SocketAddr>, headers: &axum::http::HeaderMap) -> String {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let first = xff.split(',').next().unwrap_or("").trim();
        if !first.is_empty() {
            return first.to_string();
        }
    }
    peer.map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Rate-limit middleware for POST /auth/login (10 requests / minute / IP).
pub async fn rate_limit_login(
    State(state): State<crate::state::AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let key = client_ip_key(&req);
    match state.login_limiter.check(&key).await {
        RateDecision::Allowed => next.run(req).await,
        RateDecision::Limited => too_many(),
    }
}

/// Rate-limit middleware for POST /auth/register (5 requests / 5 min / IP).
pub async fn rate_limit_register(
    State(state): State<crate::state::AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let key = client_ip_key(&req);
    match state.register_limiter.check(&key).await {
        RateDecision::Allowed => next.run(req).await,
        RateDecision::Limited => too_many(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_up_to_limit_then_blocks() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            assert!(matches!(
                limiter.check("1.2.3.4").await,
                RateDecision::Allowed
            ));
        }
        assert!(matches!(
            limiter.check("1.2.3.4").await,
            RateDecision::Limited
        ));
        // Different key is unaffected.
        assert!(matches!(
            limiter.check("5.6.7.8").await,
            RateDecision::Allowed
        ));
    }

    #[tokio::test]
    async fn window_reset() {
        let limiter = RateLimiter::new(1, Duration::from_millis(50));
        assert!(matches!(limiter.check("a").await, RateDecision::Allowed));
        assert!(matches!(limiter.check("a").await, RateDecision::Limited));
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(matches!(limiter.check("a").await, RateDecision::Allowed));
    }
}
