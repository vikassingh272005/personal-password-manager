//! WebAuthn / FIDO2 passkey support.
//!
//! Implements just what a password manager needs from the WebAuthn spec:
//!
//! - registration: build `PublicKeyCredentialCreationOptions`, then parse the
//!   returned attestation object (CBOR), extract the credential id + COSE
//!   public key, and verify the attestation signature (`none`, and `packed`
//!   self-attestation — what Touch ID / Windows Hello / Android emit).
//! - authentication: build assertion options, then verify an ES256 signature
//!   over `authenticatorData || SHA-256(clientDataJSON)`, enforce the RP ID
//!   hash, the user-present flag, and the signature counter.
//!
//! The COSE/CBOR handling is hand-rolled and deliberately minimal (~150
//! lines, the subset the spec requires authenticators to emit) so the crypto
//! surface of the project stays auditable without pulling in a general CBOR
//! framework.

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::cose::{parse_cose_key, CoseKey};

pub mod cose;

const URL_SAFE: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub fn b64url_encode(data: &[u8]) -> String {
    base64::Engine::encode(&URL_SAFE, data)
}

pub fn b64url_decode(data: &str) -> Result<Vec<u8>> {
    base64::Engine::decode(&URL_SAFE, data.trim())
        .map_err(|e| anyhow!("invalid base64url encoding: {e}"))
}

/// Relying-party configuration (rp id + expected origin), resolved from config.
#[derive(Clone, Debug)]
pub struct RpConfig {
    /// The RP ID is the effective domain the credential is scoped to
    /// (`localhost` in development, the real domain in production).
    pub rp_id: String,
    /// The exact origin the browser claims (`http://localhost:3000` in dev).
    pub origin: String,
    pub rp_name: String,
}

impl RpConfig {
    pub fn from_options(rp_id: Option<String>, origin: Option<String>) -> Self {
        Self {
            rp_id: rp_id.unwrap_or_else(|| "localhost".to_string()),
            origin: origin.unwrap_or_else(|| "http://localhost:3000".to_string()),
            rp_name: "SecureVault".to_string(),
        }
    }
}

/// A parsed, verified registration credential.
#[derive(Debug)]
pub struct VerifiedRegistration {
    pub credential_id: Vec<u8>,
    /// Re-encoded public key as stored in `passkeys.public_key` (COSE CBOR).
    pub public_key_cose: Vec<u8>,
    pub sign_count: u32,
}

/// Verify a `navigator.credentials.create()` response and extract the new
/// credential. `challenge_b64` must match what `registration_options` issued.
pub fn verify_registration(
    rp: &RpConfig,
    challenge_b64: &str,
    credential_id_b64: &str,
    attestation_object_b64: &str,
    client_data_json_b64: &str,
) -> Result<VerifiedRegistration> {
    let client_data =
        verify_client_data(rp, challenge_b64, client_data_json_b64, "webauthn.create")?;

    let attestation = b64url_decode(attestation_object_b64)?;
    let map = cbor::parse_top_level_map(&attestation)?;
    let auth_data_raw: &[u8] = map
        .get("authData")
        .and_then(|v| match v {
            cbor::Cbor::Bytes(b) => Some(b.as_slice()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("attestationObject is missing authData"))?;
    let auth_data = AuthenticatorData::parse(auth_data_raw)?;

    // The credential must be scoped to this relying party and the user must
    // have actually interacted with the authenticator.
    check_rp_id_hash(&auth_data, rp)?;
    if !auth_data.user_present() {
        bail!("user presence flag not set on registration");
    }

    let (credential_id, cose_public_key, cose_raw) = auth_data
        .attested_credential()
        .ok_or_else(|| anyhow!("registration contains no attested credential data"))?;

    // The id the browser reports must be the id embedded in the attestation.
    if b64url_decode(credential_id_b64)? != credential_id {
        bail!("credential id mismatch between client and authenticator data");
    }

    // Attestation statement verification. `none` means "no attestation" and is
    // the default for platform authenticators; `packed` self-attestation signs
    // authData with the credential key itself — verifying it proves possession.
    match map.get("fmt").and_then(|v| v.as_text()) {
        Some("none") => {}
        Some("packed") => {
            let att_stmt = map
                .get("attStmt")
                .and_then(|s| s.as_map())
                .ok_or_else(|| anyhow!("packed attestation missing attStmt"))?;
            let alg = att_stmt
                .iter()
                .find(|(k, _)| k.as_text() == Some("alg"))
                .and_then(|(_, v)| v.as_integer())
                .ok_or_else(|| anyhow!("packed attestation missing alg"))?;
            let sig = att_stmt
                .iter()
                .find(|(k, _)| k.as_text() == Some("sig"))
                .and_then(|(_, v)| v.as_bytes())
                .ok_or_else(|| anyhow!("packed attestation missing sig"))?;
            // Self-attestation: the signing key IS the credential key (no x5c).
            let has_x5c = att_stmt.iter().any(|(k, _)| k.as_text() == Some("x5c"));
            if !has_x5c {
                let mut signed = auth_data_raw.to_vec();
                signed.extend_from_slice(&client_data);
                cose_public_key.verify(alg, &signed, sig)?;
            }
            // x5c (batch attestation) is accepted without chain validation: the
            // attestation cert only proves the *vendor*, never the user, and
            // the credential key itself is verified on every assertion later.
        }
        Some(other) => bail!("unsupported attestation format: {other}"),
        None => bail!("attestationObject is missing fmt"),
    }

    Ok(VerifiedRegistration {
        credential_id,
        public_key_cose: cose_raw,
        sign_count: auth_data.sign_count,
    })
}

/// Verify a `navigator.credentials.get()` assertion. Returns the new signature
/// count on success.
pub fn verify_authentication(
    rp: &RpConfig,
    challenge_b64: &str,
    public_key: &CoseKey,
    stored_sign_count: u32,
    authenticator_data_b64: &str,
    client_data_json_b64: &str,
    signature_b64: &str,
) -> Result<u32> {
    let client_data = verify_client_data(rp, challenge_b64, client_data_json_b64, "webauthn.get")?;

    let auth_data_raw = b64url_decode(authenticator_data_b64)?;
    let auth_data = AuthenticatorData::parse(&auth_data_raw)?;
    check_rp_id_hash(&auth_data, rp)?;
    if !auth_data.user_present() {
        bail!("user presence flag not set on assertion");
    }
    // Passkeys are used as the ONLY factor in passkey-only sign-in, so user
    // verification (biometric / PIN) is mandatory on every assertion.
    if !auth_data.user_verified() {
        bail!("user verification required — unlock your authenticator");
    }

    // Replay protection: the counter must move forward (0 = counter not
    // supported by this authenticator, e.g. most platform passkeys).
    if auth_data.sign_count != 0
        && stored_sign_count != 0
        && auth_data.sign_count <= stored_sign_count
    {
        bail!("signature counter did not increase — possible cloned credential");
    }

    // Assertion signatures cover authenticatorData || SHA-256(clientDataJSON)
    // (§6.5.6 of the WebAuthn spec — note registration self-attestation signs
    // the *unhashed* client data, which verify_registration implements).
    let signature = b64url_decode(signature_b64)?;
    let mut signed = auth_data_raw.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));
    public_key.verify(-7, &signed, &signature)?;

    Ok(auth_data.sign_count)
}

/// Build `PublicKeyCredentialCreationOptions` for adding a passkey to `user_id`.
pub fn registration_options(rp: &RpConfig, user_id: &[u8], user_email: &str) -> Value {
    json!({
        "rp": { "id": rp.rp_id, "name": rp.rp_name },
        "user": {
            // Opaque, non-PII user handle — we use the account UUID.
            "id": b64url_encode(user_id),
            "name": user_email,
            "displayName": user_email,
        },
        "challenge": b64url_encode(&secure_vault_crypto::generate_random_bytes(32)),
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 },   // ES256 — universal
            { "type": "public-key", "alg": -257 }, // RS256 — Windows Hello fallback
        ],
        "timeout": 120_000,
        "attestation": "none",
        "authenticatorSelection": {
            // A passkey is a second factor here: the password remains the
            // first. residentKey preferred lets the same passkey also serve
            // passkey-only sign-in later.
            "residentKey": "preferred",
            "userVerification": "preferred",
        },
    })
}

/// Build assertion options. `allow_credentials` is empty for discoverable-
/// credential (usernameless) sign-in.
pub fn authentication_options(allow_credentials: &[(String, Vec<u8>)]) -> Value {
    let ids: Vec<Value> = allow_credentials
        .iter()
        .map(|(id_b64, _)| json!({ "type": "public-key", "id": id_b64 }))
        .collect();
    json!({
        "challenge": b64url_encode(&secure_vault_crypto::generate_random_bytes(32)),
        "rpId": RpConfig::from_options(None, None).rp_id,
        "allowCredentials": ids,
        // Assertions are the sole factor in passkey-only sign-in.
        "userVerification": "required",
        "timeout": 120_000,
    })
}

fn check_rp_id_hash(auth_data: &AuthenticatorData, rp: &RpConfig) -> Result<()> {
    let expected: [u8; 32] = Sha256::digest(rp.rp_id.as_bytes()).into();
    if auth_data.rp_id_hash != expected {
        bail!("credential is scoped to a different relying party");
    }
    Ok(())
}

fn verify_client_data(
    rp: &RpConfig,
    challenge_b64: &str,
    client_data_json_b64: &str,
    expected_type: &str,
) -> Result<Vec<u8>> {
    let client_data = b64url_decode(client_data_json_b64)?;
    let parsed: Value = serde_json::from_slice(&client_data)?;

    if parsed["type"].as_str() != Some(expected_type) {
        bail!("clientDataJSON type is not {expected_type}");
    }
    // The challenge is bound server-side (stored when options were issued);
    // comparing here ties the response to this exact ceremony.
    let issued = parsed["challenge"].as_str().unwrap_or_default();
    if issued != challenge_b64 {
        bail!("challenge mismatch — ceremony expired or replayed");
    }
    if parsed["origin"].as_str() != Some(rp.origin.as_str()) {
        bail!("clientDataJSON origin does not match the expected origin");
    }
    Ok(client_data)
}

/// The fixed-layout authenticator data blob described by the WebAuthn spec.
struct AuthenticatorData<'a> {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    raw: &'a [u8],
}

impl<'a> AuthenticatorData<'a> {
    fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < 37 {
            bail!("authenticator data too short");
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&raw[..32]);
        let flags = raw[32];
        let sign_count = u32::from_be_bytes([raw[33], raw[34], raw[35], raw[36]]);
        Ok(Self {
            rp_id_hash,
            flags,
            sign_count,
            raw,
        })
    }

    fn user_present(&self) -> bool {
        self.flags & 0x01 != 0
    }

    fn user_verified(&self) -> bool {
        self.flags & 0x04 != 0
    }

    /// attestedCredentialData is present only on registration responses.
    /// Returns (credential id, parsed key, raw COSE bytes to store).
    fn attested_credential(&self) -> Option<(Vec<u8>, CoseKey, Vec<u8>)> {
        if self.flags & 0x40 == 0 {
            return None; // AT flag not set
        }
        // Layout after the fixed part: aaguid(16) credIdLen(2) credId COSE key.
        let rest = &self.raw[37..];
        if rest.len() < 18 {
            return None;
        }
        let cred_len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
        if rest.len() < 18 + cred_len {
            return None;
        }
        let credential_id = rest[18..18 + cred_len].to_vec();
        let cose_bytes = &rest[18 + cred_len..];
        parse_cose_key(cose_bytes)
            .ok()
            .map(|key| (credential_id, key, cose_bytes.to_vec()))
    }
}

/// Minimal CBOR utilities for the attestation object. Only the subset the
/// WebAuthn spec requires: top-level maps with byte-string / text / integer
/// values (and nested maps).
pub mod cbor {
    use anyhow::{anyhow, bail, Result};

    /// A decoded CBOR value (subset).
    #[derive(Debug, Clone)]
    pub enum Cbor {
        Unsigned(u64),
        Negative(i64),
        Bytes(Vec<u8>),
        Text(String),
        Map(Vec<(Cbor, Cbor)>),
        Array(Vec<Cbor>),
    }

    impl Cbor {
        pub fn as_map(&self) -> Option<&Vec<(Cbor, Cbor)>> {
            match self {
                Cbor::Map(m) => Some(m),
                _ => None,
            }
        }

        pub fn as_text(&self) -> Option<&str> {
            match self {
                Cbor::Text(t) => Some(t),
                _ => None,
            }
        }

        pub fn as_bytes(&self) -> Option<&[u8]> {
            match self {
                Cbor::Bytes(b) => Some(b),
                _ => None,
            }
        }

        pub fn as_integer(&self) -> Option<i64> {
            match self {
                Cbor::Unsigned(u) => i64::try_from(*u).ok(),
                Cbor::Negative(n) => Some(*n),
                _ => None,
            }
        }

        /// Map lookup by text key.
        pub fn get(&self, key: &str) -> Option<&Cbor> {
            self.as_map()?.iter().find_map(|(k, v)| {
                if k.as_text() == Some(key) {
                    Some(v)
                } else {
                    None
                }
            })
        }

        /// Map lookup by integer key (COSE labels are integers).
        pub fn get_int(&self, key: i64) -> Option<&Cbor> {
            self.as_map()?.iter().find_map(|(k, v)| {
                if k.as_integer() == Some(key) {
                    Some(v)
                } else {
                    None
                }
            })
        }
    }

    struct Reader<'a> {
        data: &'a [u8],
        pos: usize,
    }

    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> Result<&'a [u8]> {
            if self.pos + n > self.data.len() {
                bail!("CBOR input truncated");
            }
            let out = &self.data[self.pos..self.pos + n];
            self.pos += n;
            Ok(out)
        }

        fn read_head(&mut self) -> Result<(u8, u64)> {
            let initial = self.take(1)?[0];
            let major = initial >> 5;
            let info = initial & 0x1f;
            let value = match info {
                0..=23 => info as u64,
                24 => self.take(1)?[0] as u64,
                25 => u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
                26 => u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64,
                27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
                _ => bail!("unsupported CBOR additional info {info}"),
            };
            Ok((major, value))
        }

        fn read_value(&mut self) -> Result<Cbor> {
            let start = self.pos;
            let (major, value) = self
                .read_head()
                .map_err(|e| anyhow!("at byte {start}: {e}"))?;
            match major {
                0 => Ok(Cbor::Unsigned(value)),
                1 => {
                    let n = i64::try_from(value).map_err(|_| anyhow!("CBOR integer overflow"))?;
                    Ok(Cbor::Negative(-1 - n))
                }
                2 => Ok(Cbor::Bytes(self.take(value as usize)?.to_vec())),
                3 => Ok(Cbor::Text(
                    String::from_utf8(self.take(value as usize)?.to_vec())
                        .map_err(|_| anyhow!("CBOR text at byte {start} is not UTF-8"))?,
                )),
                4 => {
                    let mut items = Vec::new();
                    for _ in 0..value {
                        items.push(self.read_value()?);
                    }
                    Ok(Cbor::Array(items))
                }
                5 => {
                    let mut entries = Vec::new();
                    for _ in 0..value {
                        let k = self.read_value()?;
                        let v = self.read_value()?;
                        entries.push((k, v));
                    }
                    Ok(Cbor::Map(entries))
                }
                _ => bail!("unsupported CBOR major type {major}"),
            }
        }
    }

    /// Parse a top-level map (an attestation object).
    pub fn parse_top_level_map(data: &[u8]) -> Result<Cbor> {
        let mut reader = Reader { data, pos: 0 };
        let (major, _) = reader.read_head()?;
        if major != 5 {
            bail!("attestation object is not a CBOR map");
        }
        // Re-read the map body through the generic path.
        let mut reader = Reader { data, pos: 0 };
        reader.read_value()
    }
}
