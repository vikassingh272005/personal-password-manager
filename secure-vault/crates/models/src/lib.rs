use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub id: Uuid,
    pub user_id: Uuid,
    pub version: i32,
    pub kdf_algorithm: String,
    pub kdf_memory: i32,
    pub kdf_iterations: i32,
    pub kdf_parallelism: i32,
    pub kdf_salt: Vec<u8>,
    pub encrypted_vault_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub device_type: Option<String>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passkey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: Vec<u8>,
    pub device_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: Option<Uuid>,
    pub event_type: String,
    pub created_at: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: Uuid,
    #[serde(rename = "type")]
    pub item_type: String,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub urls: Vec<String>,
    pub notes: Option<String>,
    pub favorite: bool,
    pub folder: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub custom_fields: Vec<CustomField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    #[serde(rename = "type")]
    pub field_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultData {
    pub format: String,
    pub version: i32,
    pub vault_id: Uuid,
    pub items: Vec<VaultItem>,
    pub folders: Vec<Folder>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub id: Uuid,
    pub name: String,
    pub parent_id: Option<Uuid>,
}
