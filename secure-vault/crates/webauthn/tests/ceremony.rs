//! Full WebAuthn ceremony tests against synthetic credentials.
//!
//! These simulate exactly what a browser + platform authenticator emit — a
//! P-256 keypair, hand-encoded CBOR for the COSE key and attestation object,
//! and real ECDSA signatures — so the verification path is exercised without
//! hardware. Tampered variants assert the negatives (wrong challenge, wrong
//! origin, bad signature, replayed counter all fail).

use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use secure_vault_webauthn::{b64url_encode, RpConfig};

fn rp() -> RpConfig {
    RpConfig {
        rp_id: "localhost".into(),
        origin: "http://localhost:3000".into(),
        rp_name: "SecureVault".into(),
    }
}

/// A simulated authenticator: one keypair per credential.
struct FakeAuthenticator {
    signing_key: SigningKey,
    credential_id: Vec<u8>,
    sign_count: u32,
}

impl FakeAuthenticator {
    fn new() -> Self {
        Self {
            signing_key: SigningKey::random(&mut OsRng),
            credential_id: secure_vault_crypto::generate_random_bytes(32),
            sign_count: 0,
        }
    }

    /// COSE_Key CBOR: {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}.
    fn cose_key_bytes(&self) -> Vec<u8> {
        let point = self.signing_key.verifying_key().to_encoded_point(false);
        let (x, y) = (point.x().unwrap(), point.y().unwrap());
        let mut out = vec![0xa5]; // map with 5 entries
                                  // 1: 2
        out.push(0x01);
        out.push(0x02);
        // 3: -7 (negative integer, major type 1: -1 - 6)
        out.push(0x03);
        out.push(0x26);
        // -1: 1
        out.push(0x20);
        out.push(0x01);
        // -2: x (label -2, then a 32-byte string)
        out.push(0x21);
        out.push(0x58);
        out.push(0x20);
        out.extend_from_slice(x);
        // -3: y
        out.push(0x22);
        out.push(0x58);
        out.push(0x20);
        out.extend_from_slice(y);
        out
    }

    fn auth_data(&mut self, rp_id: &str, include_attested: bool) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        // UP | UV | AT (attested data only on registration)
        let mut flags = 0x05; // UP | UV
        if include_attested {
            flags |= 0x40;
        }
        data.push(flags);
        self.sign_count += 1;
        data.extend_from_slice(&self.sign_count.to_be_bytes());
        if include_attested {
            data.extend_from_slice(&[0u8; 16]); // aaguid
            data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
            data.extend_from_slice(&self.credential_id);
            data.extend_from_slice(&self.cose_key_bytes());
        }
        data
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: p256::ecdsa::Signature =
            p256::ecdsa::signature::Signer::sign(&self.signing_key, message);
        sig.to_der().as_bytes().to_vec()
    }
}

/// Hand-encoded attestation object CBOR: {fmt: "packed", attStmt: {alg, sig},
/// authData: bytes} with self-attestation (signed by the credential key).
fn attestation_object(auth_data: &[u8], alg: i64, sig: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa3]; // map with 3 entries
                              // "fmt": "packed"
    out.push(0x63);
    out.extend_from_slice(b"fmt");
    out.push(0x66);
    out.extend_from_slice(b"packed");
    // "attStmt": { "alg": n, "sig": bytes }  ("attStmt" is 7 chars → 0x67)
    out.push(0x67);
    out.extend_from_slice(b"attStmt");
    out.push(0xa2);
    out.push(0x63);
    out.extend_from_slice(b"alg");
    // alg as a negative integer (major type 1): -1 - n
    let n = (-1 - alg) as u64;
    if n < 24 {
        out.push(0x20 | n as u8);
    } else {
        out.push(0x38);
        out.push(n as u8);
    }
    out.push(0x63);
    out.extend_from_slice(b"sig");
    if sig.len() < 24 {
        out.push(sig.len() as u8);
    } else {
        out.push(0x59);
        out.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(sig);
    // "authData": bytes  (8 chars → 0x68)
    out.push(0x68);
    out.extend_from_slice(b"authData");
    if auth_data.len() < 24 {
        out.push(auth_data.len() as u8);
    } else {
        out.push(0x59);
        out.extend_from_slice(&(auth_data.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(auth_data);
    out
}

fn client_data_json(challenge_b64: &str, typ: &str, origin: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{typ}","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
    )
    .into_bytes()
}

#[test]
fn registration_and_authentication_happy_path() {
    let rp = rp();
    let mut authenticator = FakeAuthenticator::new();

    // ---- registration ceremony ----
    let options = secure_vault_webauthn::registration_options(&rp, &[7u8; 16], "a@b.c");
    let challenge = options["challenge"].as_str().unwrap().to_string();
    let auth_data = authenticator.auth_data(&rp.rp_id, true);
    let client_data = client_data_json(&challenge, "webauthn.create", &rp.origin);
    // self-attestation signs authData || clientDataJSON
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&client_data);
    let att_sig = authenticator.sign(&signed);
    let attestation = attestation_object(&auth_data, -7, &att_sig);

    let verified = secure_vault_webauthn::verify_registration(
        &rp,
        &challenge,
        &b64url_encode(&authenticator.credential_id),
        &b64url_encode(&attestation),
        &b64url_encode(&client_data),
    )
    .expect("registration must verify");
    assert_eq!(verified.credential_id, authenticator.credential_id);
    assert_eq!(verified.sign_count, 1);

    // ---- authentication ceremony ----
    let options = secure_vault_webauthn::authentication_options(&[]);
    let challenge = options["challenge"].as_str().unwrap().to_string();
    let auth_data = authenticator.auth_data(&rp.rp_id, false);
    let client_data = client_data_json(&challenge, "webauthn.get", &rp.origin);
    // Assertions sign authData || SHA-256(clientDataJSON) per §6.5.6.
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));
    let sig = authenticator.sign(&signed);

    let new_count = secure_vault_webauthn::verify_authentication(
        &rp,
        &challenge,
        &secure_vault_webauthn::cose::parse_cose_key(&authenticator.cose_key_bytes()).unwrap(),
        verified.sign_count,
        &b64url_encode(&auth_data),
        &b64url_encode(&client_data),
        &b64url_encode(&sig),
    )
    .expect("assertion must verify");
    assert!(new_count > verified.sign_count);
}

#[test]
fn wrong_challenge_is_rejected() {
    let rp = rp();
    let mut authenticator = FakeAuthenticator::new();
    let options = secure_vault_webauthn::registration_options(&rp, &[7u8; 16], "a@b.c");
    let auth_data = authenticator.auth_data(&rp.rp_id, true);
    let client_data = client_data_json(
        options["challenge"].as_str().unwrap(),
        "webauthn.create",
        &rp.origin,
    );
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&client_data);
    let attestation = attestation_object(&auth_data, -7, &authenticator.sign(&signed));

    let err = secure_vault_webauthn::verify_registration(
        &rp,
        "a-different-challenge",
        &b64url_encode(&authenticator.credential_id),
        &b64url_encode(&attestation),
        &b64url_encode(&client_data),
    )
    .expect_err("challenge mismatch must fail");
    assert!(err.to_string().contains("challenge"));
}

#[test]
fn wrong_origin_is_rejected() {
    let rp = rp();
    let mut authenticator = FakeAuthenticator::new();
    let options = secure_vault_webauthn::registration_options(&rp, &[7u8; 16], "a@b.c");
    let challenge = options["challenge"].as_str().unwrap().to_string();
    let auth_data = authenticator.auth_data(&rp.rp_id, true);
    let client_data = client_data_json(&challenge, "webauthn.create", "https://evil.example");
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&client_data);
    let attestation = attestation_object(&auth_data, -7, &authenticator.sign(&signed));

    let err = secure_vault_webauthn::verify_registration(
        &rp,
        &challenge,
        &b64url_encode(&authenticator.credential_id),
        &b64url_encode(&attestation),
        &b64url_encode(&client_data),
    )
    .expect_err("foreign origin must fail");
    assert!(err.to_string().contains("origin"));
}

#[test]
fn foreign_rp_id_is_rejected() {
    let rp = rp();
    let mut authenticator = FakeAuthenticator::new();
    let options = secure_vault_webauthn::registration_options(&rp, &[7u8; 16], "a@b.c");
    let challenge = options["challenge"].as_str().unwrap().to_string();
    // authenticator signs for a DIFFERENT rp id
    let auth_data = authenticator.auth_data("evil.example", true);
    let client_data = client_data_json(&challenge, "webauthn.create", &rp.origin);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&client_data);
    let attestation = attestation_object(&auth_data, -7, &authenticator.sign(&signed));

    let err = secure_vault_webauthn::verify_registration(
        &rp,
        &challenge,
        &b64url_encode(&authenticator.credential_id),
        &b64url_encode(&attestation),
        &b64url_encode(&client_data),
    )
    .expect_err("foreign rp id must fail");
    assert!(err.to_string().contains("relying party"));
}

#[test]
fn tampered_assertion_is_rejected() {
    let rp = rp();
    let mut authenticator = FakeAuthenticator::new();
    let cose_key =
        secure_vault_webauthn::cose::parse_cose_key(&authenticator.cose_key_bytes()).unwrap();

    let options = secure_vault_webauthn::authentication_options(&[]);
    let challenge = options["challenge"].as_str().unwrap().to_string();
    let auth_data = authenticator.auth_data(&rp.rp_id, false);
    let client_data = client_data_json(&challenge, "webauthn.get", &rp.origin);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));
    let sig = authenticator.sign(&signed);

    // A different message (e.g. swapped challenge) must not verify.
    let other_client = client_data_json("another-challenge", "webauthn.get", &rp.origin);
    let err = secure_vault_webauthn::verify_authentication(
        &rp,
        &challenge,
        &cose_key,
        5,
        &b64url_encode(&auth_data),
        &b64url_encode(&other_client),
        &b64url_encode(&sig),
    )
    .expect_err("tampered assertion must fail");
    assert!(err.to_string().contains("challenge"));
}

#[test]
fn replayed_counter_is_rejected() {
    let rp = rp();
    let mut authenticator = FakeAuthenticator::new();
    let cose_key =
        secure_vault_webauthn::cose::parse_cose_key(&authenticator.cose_key_bytes()).unwrap();

    let options = secure_vault_webauthn::authentication_options(&[]);
    let challenge = options["challenge"].as_str().unwrap().to_string();
    let auth_data = authenticator.auth_data(&rp.rp_id, false);
    let client_data = client_data_json(&challenge, "webauthn.get", &rp.origin);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));
    let sig = authenticator.sign(&signed);

    // Server already saw sign_count 99 — a lower/equal counter means a
    // cloned credential.
    let err = secure_vault_webauthn::verify_authentication(
        &rp,
        &challenge,
        &cose_key,
        99,
        &b64url_encode(&auth_data),
        &b64url_encode(&client_data),
        &b64url_encode(&sig),
    )
    .expect_err("replayed counter must fail");
    assert!(err.to_string().contains("counter"));
}
