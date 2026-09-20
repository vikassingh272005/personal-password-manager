use axum::Json;
use serde_json::Value;

use crate::errors::AppError;

pub async fn list_items() -> Result<Json<Value>, AppError> {
    Ok(Json(serde_json::json!({
        "message": "Item operations are performed client-side on encrypted vault"
    })))
}
