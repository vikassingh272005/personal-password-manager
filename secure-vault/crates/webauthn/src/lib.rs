use anyhow::Result;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyRegistration {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub name: Option<String>,
}

pub struct WebAuthnService;

impl WebAuthnService {
    pub fn generate_registration_options(
        _user_id: Uuid,
        _user_email: &str,
    ) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "challenge": base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                secure_vault_crypto::generate_random_bytes(32)
            ),
            "rp": {
                "name": "SecureVault",
                "id": "localhost"
            },
            "userVerification": "preferred"
        }))
    }

    pub fn verify_registration(_credential_id: &[u8], _public_key: &[u8]) -> Result<bool> {
        Ok(true)
    }

    pub fn generate_authentication_options(
        _credential_ids: &[Vec<u8>],
    ) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "challenge": base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                secure_vault_crypto::generate_random_bytes(32)
            ),
            "userVerification": "preferred"
        }))
    }

    pub fn verify_authentication(
        _credential_id: &[u8],
        _signature: &[u8],
        _authenticator_data: &[u8],
        _client_data_json: &[u8],
    ) -> Result<bool> {
        Ok(true)
    }
}
