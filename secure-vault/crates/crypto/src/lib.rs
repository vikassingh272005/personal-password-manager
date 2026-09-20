use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use aes_gcm::aead::rand_core::RngCore;
use argon2::{
    password_hash::{rand_core::OsRng as ArgonOsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier, Algorithm, Version, Params,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod totp;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid key")]
    InvalidKey,
    #[error("KDF error: {0}")]
    KdfError(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptionEnvelope {
    pub version: u8,
    pub algorithm: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Zeroize)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

#[derive(Debug, Clone)]
pub struct KdfParams {
    pub algorithm: String,
    pub memory: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: "Argon2id".to_string(),
            memory: 65536,
            iterations: 3,
            parallelism: 2,
        }
    }
}

pub fn derive_key_from_password(password: &str, salt: &[u8], params: &KdfParams) -> Result<SecureBuffer, CryptoError> {
    let argon2_params = Params::new(
        params.memory,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key = vec![0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    Ok(SecureBuffer::new(key))
}

pub fn derive_subkey(master_key: &[u8], info: &[u8]) -> Result<SecureBuffer, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(master_key), b"secure-vault-key-derivation");
    let mut subkey = vec![0u8; 32];
    hk.expand(info, &mut subkey)
        .map_err(|_| CryptoError::KdfError("HKDF expansion failed".to_string()))?;
    Ok(SecureBuffer::new(subkey))
}

pub fn encrypt(plaintext: &[u8], key: &[u8], aad: Option<&[u8]>) -> Result<EncryptionEnvelope, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, aes_gcm::aead::Payload {
            msg: plaintext,
            aad: aad.unwrap_or(b""),
        })
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(EncryptionEnvelope {
        version: 1,
        algorithm: "AES-256-GCM".to_string(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

pub fn decrypt(envelope: &EncryptionEnvelope, key: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;

    let nonce = Nonce::from_slice(&envelope.nonce);

    let plaintext = cipher
        .decrypt(nonce, aes_gcm::aead::Payload {
            msg: &envelope.ciphertext,
            aad: aad.unwrap_or(b""),
        })
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext)
}

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn generate_random_string(len: usize) -> String {
    use rand::Rng;
    let mut rng = OsRng;
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..62);
            match idx {
                0..26 => (b'a' + idx) as char,
                26..52 => (b'A' + (idx - 26)) as char,
                _ => (b'0' + (idx - 52)) as char,
            }
        })
        .collect()
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut ArgonOsRng);
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn encrypt_vault_key_placeholder(master_password: &str, salt: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let kek = derive_key_from_password(master_password, salt, &KdfParams::default())?;
    let random_vek = generate_random_bytes(32);
    let envelope = encrypt(&random_vek, kek.as_bytes(), Some(b"vault-key-wrap"))?;
    serde_json::to_vec(&envelope).map_err(|_| CryptoError::EncryptionFailed)
}

pub fn decrypt_vault_key(encrypted_vault_key: &[u8], master_password: &str, salt: &[u8]) -> Result<SecureBuffer, CryptoError> {
    let kek = derive_key_from_password(master_password, salt, &KdfParams::default())?;
    let envelope: EncryptionEnvelope = serde_json::from_slice(encrypted_vault_key)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let vek_bytes = decrypt(&envelope, kek.as_bytes(), Some(b"vault-key-wrap"))?;
    Ok(SecureBuffer::new(vek_bytes))
}

pub fn generate_password(
    length: usize,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    symbols: bool,
) -> String {
    use rand::Rng;
    let mut rng = OsRng;
    let mut charset: Vec<u8> = Vec::new();

    if uppercase {
        charset.extend(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if lowercase {
        charset.extend(b"abcdefghijklmnopqrstuvwxyz");
    }
    if numbers {
        charset.extend(b"0123456789");
    }
    if symbols {
        charset.extend(b"!@#$%^&*()_+-=[]{}|;:,.<>?");
    }

    if charset.is_empty() {
        charset.extend(b"abcdefghijklmnopqrstuvwxyz");
    }

    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_random_bytes(32);
        let plaintext = b"Hello, SecureVault!";
        let envelope = encrypt(plaintext, &key, None).unwrap();
        let decrypted = decrypt(&envelope, &key, None).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = generate_random_bytes(32);
        let key2 = generate_random_bytes(32);
        let plaintext = b"Secret data";
        let envelope = encrypt(plaintext, &key1, None).unwrap();
        let result = decrypt(&envelope, &key2, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_modified_ciphertext_fails() {
        let key = generate_random_bytes(32);
        let plaintext = b"Secret data";
        let mut envelope = encrypt(plaintext, &key, None).unwrap();
        if !envelope.ciphertext.is_empty() {
            envelope.ciphertext[0] ^= 0xff;
        }
        let result = decrypt(&envelope, &key, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_password_hash_verify() {
        let password = "my-secure-password";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong-password", &hash).unwrap());
    }

    #[test]
    fn test_kdf_derivation() {
        let salt = generate_random_bytes(32);
        let key1 = derive_key_from_password("password", &salt, &KdfParams::default()).unwrap();
        let key2 = derive_key_from_password("password", &salt, &KdfParams::default()).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_generate_password() {
        let pw = generate_password(32, true, true, true, true);
        assert_eq!(pw.len(), 32);
    }
}
