use axum::Json;
use serde_json::{json, Value};

use crate::state::AppState;

pub async fn health_check() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

pub async fn readiness_check(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => Ok(Json(json!({ "status": "ready" }))),
        Err(_) => Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not ready" })),
        )),
    }
}
