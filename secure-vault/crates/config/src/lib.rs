use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Deployment environment marker. `production` switches on secure-by-default
/// behavior (Secure cookies, first-user-admin bootstrap disabled).
pub const ENV_DEVELOPMENT: &str = "development";
pub const ENV_PRODUCTION: &str = "production";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub database_url: String,
    pub session_secret: String,
    pub port: u16,
    pub cors_origins: Vec<String>,
    pub webauthn_rp_id: Option<String>,
    pub webauthn_origin: Option<String>,
    /// Emails granted the admin role. Empty means the first registered account
    /// becomes admin — but only outside production (see `first_user_is_admin`).
    pub admin_emails: Vec<String>,
    /// Secure cookies flag (default). Under a `production` APP_ENV this is
    /// forced on and warnings are emitted when it is explicitly disabled.
    pub cookie_secure: bool,
    /// How many encrypted snapshots to keep per user during normal sync.
    /// Older snapshots are pruned by a periodic cleanup task. `0` keeps all.
    pub snapshot_retention_count: u32,
    /// `"development"` (default) or `"production"`. Production mode disables
    /// the first-user-becomes-admin bootstrap and forces Secure cookies.
    pub app_env: String,
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
            cookie_secure: false,
            snapshot_retention_count: 20,
            app_env: ENV_DEVELOPMENT.to_string(),
        }
    }
}

fn env_bool(name: &str) -> Option<bool> {
    match std::env::var(name)
        .ok()?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

impl AppConfig {
    pub fn is_production(&self) -> bool {
        self.app_env == ENV_PRODUCTION
    }

    pub fn from_env() -> Result<Self> {
        let app_env = std::env::var("APP_ENV")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| ENV_DEVELOPMENT.to_string());
        let is_production = app_env == ENV_PRODUCTION;

        let cookie_secure = match env_bool("COOKIE_SECURE") {
            Some(v) => {
                if is_production && !v {
                    tracing::warn!(
                        "COOKIE_SECURE=false in production — session cookies will lack the Secure attribute (HTTP-only deployments only)"
                    );
                }
                v
            }
            None => is_production, // secure by default in production
        };

        // Production guard: an unconfigured public deployment must never grant
        // admin to whoever registers first.
        if is_production
            && std::env::var("ADMIN_EMAILS")
                .map(|v| v.trim().is_empty())
                .unwrap_or(true)
        {
            tracing::warn!(
                "ADMIN_EMAILS is empty in production — the first-user-becomes-admin bootstrap is DISABLED. \
                 Register accounts, then promote an admin via SQL: UPDATE users SET role = 'admin' WHERE email = '...';"
            );
        }

        let snapshot_retention_count = std::env::var("SNAPSHOT_RETENTION_COUNT")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(20);

        Ok(Self {
            database_url: std::env::var("DATABASE_URL").unwrap_or_else(|_| {
                "postgres://postgres:postgres@localhost:5432/secure_vault".to_string()
            }),
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
            cookie_secure,
            snapshot_retention_count,
            app_env,
        })
    }

    /// Build the Set-Cookie attribute list for the session cookie.
    ///
    /// In production mode the Secure attribute is always applied (overriding
    /// an explicit `COOKIE_SECURE=false`, which is itself warned about at
    /// startup); local HTTP development stays cookie-insecure on purpose.
    pub fn session_cookie_attributes(&self) -> String {
        let secure = if self.is_production() {
            true
        } else {
            self.cookie_secure
        };
        if secure {
            "; Secure".to_string()
        } else {
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_development() {
        let c = AppConfig::default();
        assert!(!c.is_production());
        assert_eq!(c.session_cookie_attributes(), "");
        assert_eq!(c.snapshot_retention_count, 20);
    }

    #[test]
    fn production_forces_secure_cookies() {
        let c = AppConfig {
            app_env: ENV_PRODUCTION.to_string(),
            cookie_secure: false, // even when explicitly false…
            ..Default::default()
        };
        assert!(c.is_production());
        assert_eq!(
            c.session_cookie_attributes(),
            "; Secure",
            "production must always set the Secure cookie attribute"
        );
    }

    #[test]
    fn cookie_secure_flag_respected_outside_production() {
        let c = AppConfig {
            cookie_secure: true,
            ..Default::default()
        };
        assert_eq!(c.session_cookie_attributes(), "; Secure");
    }
}
