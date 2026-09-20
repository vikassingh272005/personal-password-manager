use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub database_url: String,
    pub session_secret: String,
    pub port: u16,
    pub cors_origins: Vec<String>,
    pub webauthn_rp_id: Option<String>,
    pub webauthn_origin: Option<String>,
    /// Emails granted the admin role. Empty means the first registered account
    /// becomes admin (convenient for local development).
    pub admin_emails: Vec<String>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/secure_vault".to_string()),
            session_secret: std::env::var("SESSION_SECRET")
                .unwrap_or_else(|_| "change-me-in-production".to_string()),
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "3001".to_string())
                .parse()?,
            cors_origins: std::env::var("CORS_ORIGINS")
                .unwrap_or_else(|_| "http://localhost:3000".to_string())
                .split(',')
                .map(String::from)
                .collect(),
            webauthn_rp_id: std::env::var("WEBAUTHN_RP_ID").ok(),
            webauthn_origin: std::env::var("WEBAUTHN_ORIGIN").ok(),
            admin_emails: std::env::var("ADMIN_EMAILS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
        })
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            database_url: "postgres://postgres:postgres@localhost:5432/secure_vault".to_string(),
            session_secret: "dev-secret".to_string(),
            port: 3001,
            cors_origins: vec!["http://localhost:3000".to_string()],
            webauthn_rp_id: None,
            webauthn_origin: None,
            admin_emails: vec![],
        }
    }
}
