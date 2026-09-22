//! SecureVault API — router and handlers library.
//!
//! Exposing `build_router` (and the module tree) as a library lets the
//! integration tests in `tests/` spin up the exact same application the binary
//! serves — same routes, same extractors, same migrations — against a
//! disposable Postgres database.

pub mod errors;
pub mod maintenance;
pub mod middleware;
pub mod routes;
pub mod state;

use axum::routing::{delete, get, patch, post, put};
use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Build the CORS layer from configuration. With an explicit origin list the
/// layer is credentialed (the session cookie must survive cross-origin calls
/// from the Next.js dev server). A `*` entry — or an empty list — keeps the
/// permissive dev default.
pub fn build_cors_layer(config: &secure_vault_config::AppConfig) -> CorsLayer {
    let permissive = || {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    };

    if config.cors_origins.iter().any(|o| o.trim() == "*") {
        return permissive();
    }

    let origins: Vec<_> = config
        .cors_origins
        .iter()
        .filter_map(|o| o.trim().parse().ok())
        .collect();

    if origins.is_empty() {
        return permissive();
    }

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
        .allow_credentials(true)
}

/// Default body-size cap (2 MiB). The largest legitimate payload is a vault
/// snapshot PUT; 2 MiB comfortably fits a big personal vault (~2,000 items)
/// while rejecting abusive uploads before they reach handlers.
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Conservative security headers applied to every response. The API serves
/// JSON only, so a restrictive CSP costs nothing and hardens any future HTML
/// surface (error pages, etc.).
async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::header;
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
            .parse()
            .unwrap(),
    );
    // HSTS is deliberately not set here: the API speaks plain HTTP behind a
    // TLS-terminating proxy in dev. Add Strict-Transport-Security at the proxy.
    res
}

/// Build the full application router.
///
/// Auth is enforced per-handler via the `AuthenticatedUser` extractor; admin
/// routes additionally call `ensure_admin`. Login, register, passkey login
/// and the TOTP challenge sit behind a per-client-IP rate limiter (in-memory,
/// per process — a single instance is the current deployment model;
/// multi-instance would move counters to Redis).
pub fn build_router(state: AppState) -> Router {
    let cors = build_cors_layer(&state.config);

    Router::new()
        .route("/health", get(routes::health::health_check))
        .route("/ready", get(routes::health::readiness_check))
        .route(
            "/api/v1/auth/register",
            post(routes::auth::register).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::middleware::rate_limit::rate_limit_register,
            )),
        )
        .route(
            "/api/v1/auth/login",
            post(routes::auth::login).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::middleware::rate_limit::rate_limit_login,
            )),
        )
        .route("/api/v1/auth/logout", post(routes::auth::logout))
        .route(
            "/api/v1/auth/refresh",
            get(routes::auth::refresh).post(routes::auth::refresh),
        )
        .route("/api/v1/auth/me", get(routes::auth::me))
        .route(
            "/api/v1/auth/2fa/setup",
            post(routes::auth::start_2fa_setup),
        )
        .route("/api/v1/auth/2fa/verify", post(routes::auth::verify_2fa))
        .route("/api/v1/auth/2fa/disable", post(routes::auth::disable_2fa))
        .route(
            "/api/v1/auth/2fa/challenge",
            // A half-session that survives a password check can otherwise
            // brute-force the 6-digit TOTP space (~1M codes). The shared
            // login limiter (10/min/IP) bounds that to a few hundred guesses
            // per day per address.
            post(routes::auth::challenge_2fa).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::middleware::rate_limit::rate_limit_login,
            )),
        )
        .route(
            "/api/v1/auth/passkeys/register/options",
            post(routes::passkeys::register_options),
        )
        .route(
            "/api/v1/auth/passkeys/register/finish",
            post(routes::passkeys::register_finish),
        )
        .route(
            "/api/v1/auth/passkeys/login/options",
            post(routes::passkeys::login_options),
        )
        .route(
            "/api/v1/auth/passkeys/login/finish",
            post(routes::passkeys::login_finish).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::middleware::rate_limit::rate_limit_login,
            )),
        )
        .route(
            "/api/v1/auth/passkeys",
            get(routes::passkeys::list_passkeys),
        )
        .route(
            "/api/v1/auth/passkeys/:passkey_id",
            delete(routes::passkeys::revoke_passkey),
        )
        .route(
            "/api/v1/vault",
            get(routes::vault::get_vault).put(routes::vault::update_vault),
        )
        .route("/api/v1/vault/keys", put(routes::vault::update_vault_keys))
        .route(
            "/api/v1/devices",
            get(routes::devices::list_devices).post(routes::devices::register_device),
        )
        .route(
            "/api/v1/devices/:device_id",
            delete(routes::devices::revoke_device),
        )
        .route("/api/v1/items", get(routes::items::list_items))
        .route("/api/v1/account", delete(routes::account::delete_account))
        .route(
            "/api/v1/admin/users/:user_id/account",
            delete(routes::account::admin_delete_account),
        )
        .route("/api/v1/admin/overview", get(routes::admin::overview))
        .route("/api/v1/admin/users", get(routes::admin::list_users))
        .route(
            "/api/v1/admin/users/:user_id/role",
            patch(routes::admin::set_role),
        )
        .route(
            "/api/v1/admin/users/:user_id/revoke-sessions",
            post(routes::admin::revoke_sessions),
        )
        .route("/api/v1/admin/audit", get(routes::admin::list_audit))
        // 413s abusive payloads before any handler runs.
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}
