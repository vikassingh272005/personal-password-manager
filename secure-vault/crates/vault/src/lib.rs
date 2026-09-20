use anyhow::Result;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use secure_vault_crypto::{self, EncryptionEnvelope, KdfParams, derive_key_from_password, encrypt, decrypt, generate_random_bytes};
use secure_vault_models::VaultData;

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedVaultSnapshot {
    pub version: i32,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub vault_id: Uuid,
}

pub struct VaultEngine;

impl VaultEngine {
    pub fn create_empty_vault(_user_id: Uuid) -> VaultData {
        VaultData {
            format: "secure-vault".to_string(),
            version: 1,
            vault_id: Uuid::new_v4(),
            items: Vec::new(),
            folders: Vec::new(),
        }
    }

    pub fn encrypt_vault(
        vault: &VaultData,
        vek: &[u8],
    ) -> Result<EncryptedVaultSnapshot> {
        let serialized = serde_json::to_vec(vault)?;
        let envelope = encrypt(&serialized, vek, Some(b"secure-vault-v1"))?;

        Ok(EncryptedVaultSnapshot {
            version: vault.version,
            ciphertext: envelope.ciphertext,
            nonce: envelope.nonce,
            vault_id: vault.vault_id,
        })
    }

    pub fn decrypt_vault(
        snapshot: &EncryptedVaultSnapshot,
        vek: &[u8],
    ) -> Result<VaultData> {
        let envelope = EncryptionEnvelope {
            version: 1,
            algorithm: "AES-256-GCM".to_string(),
            nonce: snapshot.nonce.clone(),
            ciphertext: snapshot.ciphertext.clone(),
        };

        let plaintext = decrypt(&envelope, vek, Some(b"secure-vault-v1"))?;
        let vault: VaultData = serde_json::from_slice(&plaintext)?;
        Ok(vault)
    }

    pub fn unlock_vault(
        master_password: &str,
        kdf_salt: &[u8],
        encrypted_vault_key: &[u8],
        encrypted_vault: &EncryptedVaultSnapshot,
    ) -> Result<VaultData> {
        let vek = secure_vault_crypto::decrypt_vault_key(encrypted_vault_key, master_password, kdf_salt)?;
        Self::decrypt_vault(encrypted_vault, vek.as_bytes())
    }

    pub fn re_encrypt_vault_key(
        old_master_password: &str,
        new_master_password: &str,
        kdf_salt: &[u8],
        encrypted_vault_key: &[u8],
    ) -> Result<Vec<u8>> {
        let vek = secure_vault_crypto::decrypt_vault_key(encrypted_vault_key, old_master_password, kdf_salt)?;

        let new_salt = generate_random_bytes(32);
        let new_kek = derive_key_from_password(new_master_password, &new_salt, &KdfParams::default())?;
        let envelope = encrypt(vek.as_bytes(), new_kek.as_bytes(), Some(b"vault-key-wrap"))?;
        serde_json::to_vec(&envelope).map_err(|e| anyhow::anyhow!(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure_vault_models::VaultItem;

    #[test]
    fn test_vault_encrypt_decrypt_roundtrip() {
        let vek = generate_random_bytes(32);
        let vault = VaultData {
            format: "secure-vault".to_string(),
            version: 1,
            vault_id: Uuid::new_v4(),
            items: vec![VaultItem {
                id: Uuid::new_v4(),
                item_type: "login".to_string(),
                title: "GitHub".to_string(),
                username: Some("user@example.com".to_string()),
                password: Some("super-secret".to_string()),
                urls: vec!["https://github.com".to_string()],
                notes: None,
                favorite: false,
                folder: Some("Development".to_string()),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                custom_fields: vec![],
            }],
            folders: vec![],
        };

        let snapshot = VaultEngine::encrypt_vault(&vault, &vek).unwrap();
        let decrypted = VaultEngine::decrypt_vault(&snapshot, &vek).unwrap();

        assert_eq!(decrypted.items.len(), 1);
        assert_eq!(decrypted.items[0].title, "GitHub");
        assert_eq!(decrypted.items[0].password.as_ref().unwrap(), "super-secret");
    }
}
