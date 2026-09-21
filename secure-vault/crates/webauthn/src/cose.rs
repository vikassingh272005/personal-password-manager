//! COSE key parsing (RFC 9052 subset) and signature verification for the two
//! algorithms WebAuthn deployments emit: ES256 (ECDSA P-256, COSE alg -7) and
//! RS256 (RSA PKCS#1 v1.5, COSE alg -257).

use anyhow::{anyhow, bail, Result};
use p256::ecdsa::{Signature, VerifyingKey};
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use rsa::signature::Verifier as _;
use sha2::Sha256;

use super::cbor::Cbor;

/// A parsed COSE public key.
#[derive(Debug, Clone)]
pub enum CoseKey {
    /// EC2 / P-256 (COSE alg -7, ES256).
    Ec2P256 {
        /// Uncompressed EC point (0x04 || X || Y), 65 bytes.
        point: Vec<u8>,
    },
    /// RSA (COSE alg -257, RS256).
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
}

impl CoseKey {
    /// Verify a signature. `alg` is the COSE algorithm id the signer claimed;
    /// it must match the key type.
    pub fn verify(&self, alg: i64, message: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            CoseKey::Ec2P256 { point } => {
                if alg != -7 {
                    bail!("EC2 key used with COSE alg {alg}");
                }
                let vk = VerifyingKey::from_sec1_bytes(point)
                    .map_err(|_| anyhow!("invalid P-256 public key point"))?;
                // Authenticators may emit DER or raw r||s encodings.
                let sig = Signature::from_der(signature)
                    .or_else(|_| Signature::from_slice(signature))
                    .map_err(|_| anyhow!("malformed ECDSA signature"))?;
                use p256::ecdsa::signature::Verifier as _;
                vk.verify(message, &sig)
                    .map_err(|_| anyhow!("ECDSA signature verification failed"))
            }
            CoseKey::Rsa { modulus, exponent } => {
                if alg != -257 {
                    bail!("RSA key used with COSE alg {alg}");
                }
                let pk = rsa::RsaPublicKey::new(
                    rsa::BigUint::from_bytes_be(modulus),
                    rsa::BigUint::from_bytes_be(exponent),
                )
                .map_err(|_| anyhow!("invalid RSA public key"))?;
                let sig = RsaSignature::try_from(signature)
                    .map_err(|_| anyhow!("malformed RSA signature"))?;
                let vk = RsaVerifyingKey::<Sha256>::new(pk);
                vk.verify(message, &sig)
                    .map_err(|_| anyhow!("RSA signature verification failed"))
            }
        }
    }
}

/// Parse a COSE_Key from raw CBOR bytes — exactly the encoding embedded in
/// attested credential data.
pub fn parse_cose_key(data: &[u8]) -> Result<CoseKey> {
    let map = super::cbor::parse_top_level_map(data)?;
    let kty = map
        .get_int(1)
        .and_then(Cbor::as_integer)
        .ok_or_else(|| anyhow!("COSE key missing kty"))?;
    let alg = map
        .get_int(3)
        .and_then(Cbor::as_integer)
        .ok_or_else(|| anyhow!("COSE key missing alg"))?;

    match kty {
        2 => {
            // EC2: crv = label -1, x = -2, y = -3.
            if map.get_int(-1).and_then(Cbor::as_integer) != Some(1) {
                bail!("unsupported EC curve (only P-256)");
            }
            let x = map
                .get_int(-2)
                .and_then(Cbor::as_bytes)
                .ok_or_else(|| anyhow!("EC2 key missing x"))?;
            let y = map
                .get_int(-3)
                .and_then(Cbor::as_bytes)
                .ok_or_else(|| anyhow!("EC2 key missing y"))?;
            if alg != -7 {
                bail!("EC2 key with unexpected COSE alg {alg}");
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            Ok(CoseKey::Ec2P256 { point })
        }
        3 => {
            let n = map
                .get_int(-1)
                .and_then(Cbor::as_bytes)
                .ok_or_else(|| anyhow!("RSA key missing n"))?;
            let e = map
                .get_int(-2)
                .and_then(Cbor::as_bytes)
                .ok_or_else(|| anyhow!("RSA key missing e"))?;
            if alg != -257 {
                bail!("RSA key with unexpected COSE alg {alg}");
            }
            Ok(CoseKey::Rsa {
                modulus: n.to_vec(),
                exponent: e.to_vec(),
            })
        }
        other => bail!("unsupported COSE key type {other}"),
    }
}
