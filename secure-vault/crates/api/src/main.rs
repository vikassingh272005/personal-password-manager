use anyhow::Result;
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use secure_vault_api::build_router;
use secure_vault_config::AppConfig;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "secure_vault_api=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = AppConfig::from_env()?;
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&config.database_url)
        .await?;

    sqlx::migrate!("../../migrations").run(&pool).await?;

    let port = config.port;
    let state = secure_vault_api::state::AppState::new(pool, config);
    let app = build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("SecureVault API listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    // ConnectInfo is required by the per-IP rate limiter on login/register.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}
