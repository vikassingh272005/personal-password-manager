//! End-to-end API integration tests: run the real router against a real
//! Postgres and exercise the auth → 2FA → vault sync flows over HTTP.
//!
//! Requires `DATABASE_URL` pointing at a disposable database (CI provides a
//! Postgres service container; locally `docker compose up -d` and
//! `DATABASE_URL=postgres://postgres:postgres@localhost:5433/secure_vault`).
//! The suite truncates all tables before it runs, so point it at a database
//! you are happy to lose.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt; // for `oneshot`

use secure_vault_api::build_router;
use secure_vault_api::state::AppState;

fn test_db_url() -> String {
    // Deliberately NOT the development database (which holds real local
    // data): the suite truncates everything it connects to. CI overrides
    // this via env with its own disposable Postgres.
    std::env::var("SECURE_VAULT_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5433/secure_vault_test".into())
}

async fn setup_test() -> (axum::Router, tokio::sync::MutexGuard<'static, ()>) {
    // Serialize BEFORE touching the database: each test truncates the shared
    // database, so concurrent setups would wipe each other's fixtures.
    let guard = DB_LOCK.lock().await;

    let url = test_db_url();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("connect to test Postgres (is it running? see docker-compose.yml)");

    // Migrate before truncating — on a pristine database the tables don't
    // exist yet. Migrations are tracked, so this is a no-op on later runs.
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("run migrations");

    // Fresh, empty tables for every run: tests create accounts with fixed
    // emails, so leftovers from previous runs would collide.
    sqlx::query("TRUNCATE audit_events, sessions, vault_snapshots, vaults, devices, users CASCADE")
        .execute(&pool)
        .await
        .expect("truncate test database");

    let config = secure_vault_config::AppConfig {
        port: 0, // unused in tests — the router is called directly
        cors_origins: vec!["http://localhost:3000".to_string()],
        admin_emails: vec![], // first registered account becomes admin
        ..secure_vault_config::AppConfig::default()
    };
    let router = build_router(AppState::new(pool, config));

    // The guard is returned and held for the whole test: the database must
    // stay untouched by other tests until this one finishes.
    (router, guard)
}

/// Serializes tests: each truncates the shared database at startup.
static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// POST JSON and return (status, body, session cookie) with the cookie value
/// extracted from any Set-Cookie header.
async fn post_json(
    app: &axum::Router,
    uri: &str,
    payload: Value,
    cookie: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(c) = cookie {
        builder = builder.header("cookie", format!("session_token={c}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(payload.to_string())).unwrap())
        .await
        .unwrap();

    let status = response.status();
    let cookie_out = response.headers().get("set-cookie").and_then(|v| {
        let s = v.to_str().ok()?;
        s.split(';')
            .next()
            .and_then(|kv| kv.strip_prefix("session_token="))
            .map(String::from)
    });
    let body = body_json(response).await;
    (status, body, cookie_out)
}

async fn get_json(app: &axum::Router, uri: &str, cookie: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("cookie", format!("session_token={cookie}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (status, body_json(response).await)
}

async fn put_json(
    app: &axum::Router,
    uri: &str,
    payload: Value,
    cookie: &str,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(uri)
                .header("content-type", "application/json")
                .header("cookie", format!("session_token={cookie}"))
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (status, body_json(response).await)
}

/// 48 bytes of base64 (32-byte key + 16-byte GCM tag) and a 12-byte nonce.
fn fake_wrap() -> Value {
    json!({
        "ciphertext": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v",
        "nonce": "AAAAAAAAAAAAAAAA"
    })
}

#[tokio::test]
async fn register_login_vault_flow() {
    let (app, _guard) = setup_test().await;

    // ---- register: creates account + vault, sets the session cookie --------
    let (status, body, cookie) = post_json(
        &app,
        "/api/v1/auth/register",
        json!({ "email": "alice@example.com", "password": "correct horse battery" }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register body: {body}");
    assert_eq!(body["email"], "alice@example.com");
    // First account with no ADMIN_EMAILS becomes admin (bootstrap rule).
    assert_eq!(body["role"], "admin");
    assert!(cookie.is_some(), "registration must establish a session");
    let alice_cookie = cookie.unwrap();

    // Duplicate registration is rejected.
    let (status, _, _) = post_json(
        &app,
        "/api/v1/auth/register",
        json!({ "email": "alice@example.com", "password": "whatever123" }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // ---- identity ----------------------------------------------------------
    let (status, me) = get_json(&app, "/api/v1/auth/me", &alice_cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["email"], "alice@example.com");
    assert_eq!(me["role"], "admin");

    // Anonymous access is rejected.
    let (status, _) = get_json(&app, "/api/v1/auth/me", "not-a-real-token").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // ---- vault sync: version must advance one step at a time ---------------
    let (status, vault) = get_json(&app, "/api/v1/vault", &alice_cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(vault["version"], 1);
    assert!(vault["kek_wrap"].is_null(), "fresh vault has no wrap yet");

    let snapshot1 = json!({
        "version": 1,
        "ciphertext": "YWJjZGVmZ2hpamtsbW5vcA==",
        "nonce": "AAAAAAAAAAAAAAAA",
        "kek_wrap": fake_wrap(),
        "recovery_wrap": Value::Null,
    });
    let (status, body) = put_json(&app, "/api/v1/vault", snapshot1, &alice_cookie).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["version"], 1);

    // Stale version is rejected with a conflict.
    let stale = json!({
        "version": 1,
        "ciphertext": "YWJjZGVmZ2hpamtsbW5vcA==",
        "nonce": "AAAAAAAAAAAAAAAA",
    });
    let (status, body) = put_json(&app, "/api/v1/vault", stale, &alice_cookie).await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");

    let (status, body) = put_json(
        &app,
        "/api/v1/vault",
        json!({
            "version": 2,
            "ciphertext": "ZGVmZ2hpamtsbW5vcHFyc3Q=",
            "nonce": "AAAAAAAAAAAAAAAC",
        }),
        &alice_cookie,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    // The latest snapshot comes back with the vault metadata.
    let (status, vault) = get_json(&app, "/api/v1/vault", &alice_cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(vault["version"], 2);
    assert!(!vault["ciphertext"].is_null());
    assert!(vault["kek_wrap"].is_object(), "kek wrap stored");

    // ---- admin surface -----------------------------------------------------
    let (status, users) = get_json(&app, "/api/v1/admin/users", &alice_cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(users.as_array().unwrap().len(), 1);
    assert_eq!(users[0]["two_factor_enabled"], false);

    // ---- register a second (non-admin) user, check the role gate -----------
    let (status, _, cookie) = post_json(
        &app,
        "/api/v1/auth/register",
        json!({ "email": "bob@example.com", "password": "hunter2 hunter2" }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let bob_cookie = cookie.unwrap();
    let (_status, me) = get_json(&app, "/api/v1/auth/me", &bob_cookie).await;
    assert_eq!(me["role"], "user");

    let (status, _) = get_json(&app, "/api/v1/admin/users", &bob_cookie).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // ---- login (password only, no 2FA yet) ---------------------------------
    let (status, body, cookie) = post_json(
        &app,
        "/api/v1/auth/login",
        json!({ "email": "alice@example.com", "password": "correct horse battery" }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(cookie.is_some());

    // Wrong password fails.
    let (status, _, _) = post_json(
        &app,
        "/api/v1/auth/login",
        json!({ "email": "alice@example.com", "password": "wrong" }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn two_factor_enroll_and_challenge_login() {
    let (app, _guard) = setup_test().await;

    // Register (first user → admin, full session).
    let (status, _, cookie) = post_json(
        &app,
        "/api/v1/auth/register",
        json!({ "email": "tfa@example.com", "password": "correct horse battery" }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let cookie = cookie.unwrap();

    // ---- enroll -------------------------------------------------------------
    let (status, setup, _) =
        post_json(&app, "/api/v1/auth/2fa/setup", json!({}), Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "body: {setup}");
    let secret = setup["secret"].as_str().unwrap().to_string();
    assert!(setup["otpauth_uri"]
        .as_str()
        .unwrap()
        .starts_with("otpauth://totp/"));

    // A wrong code does not enable 2FA.
    let (status, _, _) = post_json(
        &app,
        "/api/v1/auth/2fa/verify",
        json!({ "code": "000000" }),
        Some(&cookie),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Compute a valid code locally for the *current* time step.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let decoded = secure_vault_crypto::totp::base32_decode(&secret).unwrap();
    let code = format!(
        "{:06}",
        secure_vault_crypto::totp::hotp_sha1(&decoded, now / 30, 6)
    );
    let (status, body, _) = post_json(
        &app,
        "/api/v1/auth/2fa/verify",
        json!({ "code": code }),
        Some(&cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    // ---- password-only login now lands in the awaiting-2FA gate ------------
    let (status, body, partial) = post_json(
        &app,
        "/api/v1/auth/login",
        json!({ "email": "tfa@example.com", "password": "correct horse battery" }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "body: {body}");
    assert_eq!(body["two_factor_required"], true);
    let partial = partial.expect("awaiting-2fa session cookie is set");

    // The half-session cannot reach anything else...
    let (status, _) = get_json(&app, "/api/v1/vault", &partial).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = get_json(&app, "/api/v1/admin/users", &partial).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // ...but can complete the challenge.
    let code = format!(
        "{:06}",
        secure_vault_crypto::totp::hotp_sha1(&decoded, now / 30, 6)
    );
    let (status, body, _) = post_json(
        &app,
        "/api/v1/auth/2fa/challenge",
        json!({ "code": code }),
        Some(&partial),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["email"], "tfa@example.com");

    // The same cookie is now a full session.
    let (status, me) = get_json(&app, "/api/v1/auth/me", &partial).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["email"], "tfa@example.com");

    // Admin sees the 2FA flag.
    let (status, users) = get_json(&app, "/api/v1/admin/users", &partial).await;
    assert_eq!(status, StatusCode::OK);
    let tfa_row = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["email"] == "tfa@example.com")
        .unwrap();
    assert_eq!(tfa_row["two_factor_enabled"], true);

    // ---- disabling requires code + password --------------------------------
    let now2 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code2 = format!(
        "{:06}",
        secure_vault_crypto::totp::hotp_sha1(&decoded, now2 / 30, 6)
    );
    // Wrong password → 401 even with a good code.
    let (status, _, _) = post_json(
        &app,
        "/api/v1/auth/2fa/disable",
        json!({ "code": code2, "password": "nope" }),
        Some(&partial),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body, _) = post_json(
        &app,
        "/api/v1/auth/2fa/disable",
        json!({ "code": code2, "password": "correct horse battery" }),
        Some(&partial),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["enabled"], false);

    // Password-only login works again.
    let (status, _, _) = post_json(
        &app,
        "/api/v1/auth/login",
        json!({ "email": "tfa@example.com", "password": "correct horse battery" }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
