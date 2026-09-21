//! SecureVault API — router and handlers library.
//!
//! Exposing `build_router` (and the module tree) as a library lets the
//! integration tests in `tests/` spin up the exact same application the binary
//! serves — same routes, same extractors, same migrations — against a
//! disposable Postgres database.

pub mod errors;
pub mod middleware;
pub mod routes;
pub mod state;

use axum::routing::{delete, get, patch, post, put};
use axum::Router;
use tower_http::cors::{Any, CorsLayer};
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

/// Build the full application router.
///
/// Auth is enforced per-handler via the `AuthenticatedUser` extractor; admin
/// routes additionally call `ensure_admin`. Login and register sit behind a
/// per-client-IP sliding-window rate limiter (in-memory, per process — a
/// single instance is the current deployment model; multi-instance would move
/// counters to Redis).
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
            post(routes::auth::challenge_2fa),
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
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}
